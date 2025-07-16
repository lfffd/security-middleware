<?php

namespace lfffd\SecurityMiddleware;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\View;
use Illuminate\Support\Facades\Log;
use Symfony\Component\Yaml\Yaml;
use Spyc;
use Closure;

class PermissionGuard
{
    protected static array $config = [];
    protected static array $variables = [];
    protected static string $bladeError = 'errors.unauthorized';

    /**
     * Initialize configuration and variables from YAML and cache.
     */
    public static function init(string $yamlFilePath, array $variables = [], string $bladeError = null): void
    {
        if ($bladeError) {
            self::$bladeError = $bladeError;
        }

        self::$variables = $variables;

        if (Cache::has('security_config')) {
            Log::info('PermissionGuard: Loading config from cache');
            self::$config = Cache::get('security_config');
            Log::info('PermissionGuard: Returning from init (config loaded from cache)');
            return;
        } else {
            Log::info('PermissionGuard: Loading config from YAML file', ['file' => $yamlFilePath]);
            $yamlContent = file_get_contents($yamlFilePath);
            self::$config = Spyc::YAMLLoadString($yamlContent);
            Cache::put('security_config', self::$config, 3600);
            Log::info('PermissionGuard: Returning from init (config loaded from YAML)');
            return;
        }
    }

    /**
     * Handle the incoming request by checking permissions.
     */
    public static function handleRequest($request)
    {
        $path = '/' . ltrim($request->path(), '/');
        $method = strtoupper($request->method());

        Log::info("PermissionGuard: Starting request validation", ['path' => $path, 'method' => $method]);

        $rulesConfig = self::matchUrlConfig($path, $method);

        if (!$rulesConfig) {
            Log::info("PermissionGuard: No matching rules found for URL", ['path' => $path]);
            $response = response()->view(self::$bladeError, ['message' => "Unauthorized URL: $path"], 403);
            Log::info("PermissionGuard: Returning unauthorized response", ['response_status' => 403]);
            return $response;
        }

        Log::info("PermissionGuard: Rules found, executing parsers", ['parsers' => $rulesConfig['parsers'] ?? []]);

        // Execute parsers
        if (!empty($rulesConfig['parsers'])) {
            foreach ($rulesConfig['parsers'] as $var => $parser) {
                Log::info("PermissionGuard: Executing parser", ['variable' => $var, 'parser' => $parser]);
                try {
                    self::parseVariable($var, $parser);
                } catch (\Throwable $e) {
                    Log::warning("PermissionGuard: Denying access due to parser error", ['error' => $e->getMessage()]);
                    return response()->view(self::$bladeError, ['message' => 'Unauthorized (model not found or invalid).'], 403);
                }
            }
        }

        Log::info("PermissionGuard: Evaluating rules", ['rules' => $rulesConfig['rules'] ?? []]);

        if (!empty($rulesConfig['rules'])) {
            foreach ($rulesConfig['rules'] as $ruleName => $rule) {
                if (str_starts_with($ruleName, '=')) {
                    $baseRuleName = substr($ruleName, 1);
                    $globalRules = self::$config['rules'] ?? [];

                    if (!isset($globalRules[$baseRuleName])) {
                        $msg = "Referenced global rule '$baseRuleName' not found in top-level rules.";
                        Log::error("PermissionGuard: $msg");
                        return response()->view(self::$bladeError, ['message' => $msg], 403);
                    }

                    $baseRule = $globalRules[$baseRuleName];

                    if (!is_array($rule)) {
                        if (!empty($rule)) {
                            Log::warning("PermissionGuard: Rule override for ={$baseRuleName} should be an array. Ignoring override.");
                        }
                        $rule = $baseRule;
                    } else {
                        $rule = array_merge($baseRule, $rule);
                    }

                    $rule['inherited_from'] = $baseRuleName;

                    Log::info("PermissionGuard: Loaded inherited rule", [
                        'inherited_from' => $baseRuleName,
                        'final_rule' => $rule
                    ]);
                }

                $result = self::evaluateRule($rule);
                Log::info("PermissionGuard: Evaluating rule", ['ruleName' => $ruleName, 'result' => $result]);

                if (!$result) {
                    $message = self::parseMessage($rule['message'] ?? "Rule $ruleName failed.");
                    Log::info("PermissionGuard: Rule failed", [
                        'ruleName' => $ruleName,
                        'inherited_from' => $rule['inherited_from'] ?? null,
                        'message' => $message
                    ]);
                    return response()->view(self::$bladeError, ['message' => $message], 403);
                }
            }
        }

        Log::info("PermissionGuard: All rules passed, access granted");
        Log::info("PermissionGuard: Returning null (continue request processing)");
        return null;
    }

    /**
     * Middleware callable to plug into Laravel's middleware stack.
     */
    public static function middleware(string $yamlPath, array $vars = [], string $bladeError = null)
    {
        return function ($request, Closure $next) use ($yamlPath, $vars, $bladeError) {
            self::init($yamlPath, $vars, $bladeError);
            $response = self::handleRequest($request);
            if ($response) {
                Log::info("PermissionGuard: Middleware returning response early");
                return $response;
            }
            Log::info("PermissionGuard: Middleware passing request to next middleware");
            return $next($request);
        };
    }

    /**
     * Match the request URL and method against the configured URL rules.
     */

    protected static function matchUrlConfig($path, $method)
    {
        $config = self::$config['urls'] ?? [];
        $requestPath = $path;
        $requestQuery = request()->getQueryString() ?? '';

        Log::info("PermissionGuard: Starting matchUrlConfig", ['path' => $requestPath, 'query' => $requestQuery, 'method' => $method]);

        $bufferedRoutes = [];

        foreach ($config as $methodAndUrl => $ruleBlock) {
            Log::info("PermissionGuard: Checking configured route key", ['route' => $methodAndUrl]);

            if (!str_contains($methodAndUrl, ' ')) {
                Log::warning("PermissionGuard: Invalid route key format, skipping", ['key' => $methodAndUrl]);
                continue;
            }

            [$configMethod, $configUrl] = explode(' ', $methodAndUrl, 2);
            $configMethod = strtoupper(trim($configMethod));
            $configUrl = trim($configUrl);

            if (!is_array($ruleBlock) || empty($ruleBlock)) {
                $bufferedRoutes[] = [$configMethod, $configUrl];
                continue;
            }

            $routesToCheck = array_merge($bufferedRoutes, [[$configMethod, $configUrl]]);
            $bufferedRoutes = [];

            foreach ($routesToCheck as [$methodToCheck, $urlToCheck]) {
                if ($methodToCheck !== $method && $methodToCheck !== 'ALL') {
                    continue;
                }

                $parts = explode('?', $urlToCheck, 2);
                $configPath = $parts[0];
                $configQuery = $parts[1] ?? '';

                // Match path and extract vars
                $patternPathVars = [];
                preg_match_all('/\$([a-zA-Z0-9_]+)/', $configPath, $patternPathVars);
                $regexPath = preg_replace('/\$([a-zA-Z0-9_]+)/', '([^/]+)', preg_quote($configPath, '/'));
                $matchesPath = [];
                if (!preg_match("~^$regexPath$~", $requestPath, $matchesPath)) {
                    Log::info("PermissionGuard: Path did not match", ['pattern' => $regexPath, 'requestPath' => $requestPath]);
                    continue;
                }

                array_shift($matchesPath);
                foreach ($patternPathVars[1] as $i => $varName) {
                    self::$variables['input'][$varName] = $matchesPath[$i];
                    Log::info("PermissionGuard: Captured path variable", ['var' => $varName, 'value' => $matchesPath[$i]]);
                }

                // Match query vars
                preg_match_all('/\$([a-zA-Z0-9_]+)/', $configQuery, $queryVars);
                foreach ($queryVars[1] as $varName) {
                    $val = request()->query($varName);
                    if ($val !== null) {
                        self::$variables['input'][$varName] = $val;
                        Log::info("PermissionGuard: Captured query variable", ['var' => $varName, 'value' => $val]);
                    }
                }

                Log::info("PermissionGuard: Returning matched rules", ['rules' => $ruleBlock]);
                return $ruleBlock;
            }
        }

        Log::info("PermissionGuard: No URL matched the requested path");
        return null;
    }

    /**
     * Parse a variable based on the parser string.
     */
    protected static function parseVariable($key, $parser)
    {
        Log::info("PermissionGuard: parseVariable called", ['key' => $key, 'parser' => $parser]);

        if (!is_string($parser)) {
            Log::warning("PermissionGuard: Parser must be a string. Skipping.", ['parser' => $parser]);
            return;
        }

        if (str_starts_with($parser, 'php:')) {
            $code = substr($parser, 4);
            Log::info("PermissionGuard: Parsing PHP code", ['code' => $code]);
            try {
                self::assignVariable($key, eval("return $code;"));
            } catch (\Throwable $e) {
                Log::error("PermissionGuard: Error executing PHP code", ['error' => $e->getMessage()]);
                self::assignVariable($key, null);
            }

        } elseif (str_starts_with($parser, 'model:')) {
            $modelExpr = trim(substr($parser, 6));
            if (str_contains($modelExpr, '::')) {
                self::handleModelEvalParser($key, $modelExpr);
            } else {
                self::handleModelParser($key, $modelExpr); // handles both single and chained models
            }
        } else {
            Log::warning("PermissionGuard: Unsupported parser prefix", ['parser' => $parser]);
        }
    }

    protected static function handlePhpParser($key, $parser)
    {
        $code = substr($parser, 4);
        Log::info("PermissionGuard: Running PHP parser", ['code' => $code]);

        try {
            $result = eval("return $code;");
            self::assignVariable($key, $result);
        } catch (\Throwable $e) {
            Log::error("PermissionGuard: Error evaluating PHP code", ['error' => $e->getMessage()]);
            self::assignVariable($key, null);
        }
    }
    protected static function handleModelParser($key, $modelPath)
    {
        $parts = explode(':', trim($modelPath));
        $lastModelName = array_pop($parts);
        $lastModelClass = "App\\Models\\$lastModelName";

        $id = self::getVarFromPathOrInput('id');

        Log::info("PermissionGuard: Resolving model chain (manual foreign key mode)", [
            'modelPath' => $modelPath,
            'id' => $id
        ]);

        try {
            $instance = $lastModelClass::find($id);

            if (!$instance) {
                Log::warning("PermissionGuard: Instance of final model not found", ['model' => $lastModelClass, 'id' => $id]);
                throw new \Exception("Final model instance not found, denying access.");
            }

            Log::info("PermissionGuard: Loaded final model", ['class' => $lastModelClass]);

            while (!empty($parts)) {
                $parentModelName = array_pop($parts);
                $foreignKey = strtolower($parentModelName) . '_id';
                $parentModelClass = "App\\Models\\$parentModelName";

                $relatedId = is_array($instance)
                    ? ($instance[$foreignKey] ?? null)
                    : ($instance->{$foreignKey} ?? null);

                if (!$relatedId) {
                    Log::warning("PermissionGuard: Could not resolve foreign key", [
                        'foreignKey' => $foreignKey,
                        'fromModel' => get_class($instance)
                    ]);
                    throw new \Exception("Missing foreign key '$foreignKey', denying access.");
                }

                $instance = $parentModelClass::find($relatedId);

                if (!$instance) {
                    Log::warning("PermissionGuard: Could not find parent model instance", [
                        'class' => $parentModelClass,
                        'id' => $relatedId
                    ]);
                    throw new \Exception("Failed to resolve model '$parentModelName', denying access.");
                }

                Log::info("PermissionGuard: Resolved parent model", [
                    'model' => $parentModelClass,
                    'id' => $relatedId
                ]);
            }

            self::assignVariable($key, $instance);
        } catch (\Throwable $e) {
            Log::error("PermissionGuard: Error in manual model resolution", [
                'error' => $e->getMessage()
            ]);
            self::assignVariable($key, null);
            throw $e;
        }
    }

    /**
     * Evaluate a rule expression.
     */
    protected static function evaluateRule(array $rule): bool
    {
        $expr = $rule['permission'] ?? $rule['permissions'] ?? null;

        if ($expr === '*') {
            Log::info("PermissionGuard: Rule is wildcard '*', automatically passing.");
            return true;
        }

        if (!$expr) {
            Log::info("PermissionGuard: Rule has no permission expression, failing.");
            return false;
        }

        $parsedExpr = self::interpolateVars($expr);

        $parsedExpr = preg_replace_callback('/(?<!["\'])\b([a-zA-Z_][a-zA-Z0-9_]*)\b(?!["\'])/', function ($matches) {
            $word = $matches[1];

            // Skip PHP literals and variables
            if (in_array(strtolower($word), ['null', 'true', 'false']) || is_numeric($word) || str_starts_with($word, '$')) {
                return $word;
            }

            // Wrap in single quotes
            return "'$word'";
        }, $parsedExpr);


        Log::info("PermissionGuard: Evaluating expression", ['expr' => $expr, 'parsed' => $parsedExpr]);

        try {
            return eval("return ($parsedExpr);");
        } catch (\Throwable $e) {
            Log::error('PermissionGuard evaluation error: ' . $e->getMessage(), ['parsed' => $parsedExpr]);
            return false;
        }
    }

    /**
     * Parse message with variable interpolation.
     */
    protected static function parseMessage($message)
    {
        Log::info("PermissionGuard: Parsing message", ['message' => $message]);
        $result = self::interpolateVars($message);
        Log::info("PermissionGuard: Parsed message", ['result' => $result]);
        return $result;
    }

    /**
     * Interpolate variables in text (replace $var with value).
     */
    protected static function interpolateVars($text)
    {
        return preg_replace_callback('/\\$([a-zA-Z0-9_\.]+)/', function ($matches) {
            $val = self::resolveVar($matches[1]);
            Log::info("PermissionGuard: Interpolating var", ['var' => $matches[1], 'value' => $val]);
            if (is_string($val) || is_numeric($val) || is_bool($val) || is_null($val)) {
                return var_export($val, true); // returns quoted strings and raw numbers
            }
            return 'null'; // non-scalar values not allowed in expressions

        }, $text);
    }

    /**
     * Resolve variable key path from stored variables.
     */
    protected static function resolveVar($key)
    {
        $segments = explode('.', $key);
        $value = self::$variables[$segments[0]] ?? null;

        for ($i = 1; $i < count($segments); $i++) {
            if (is_array($value) && isset($value[$segments[$i]])) {
                $value = $value[$segments[$i]];
            } elseif (is_object($value) && isset($value->{$segments[$i]})) {
                $value = $value->{$segments[$i]};
            } else {
                Log::info("PermissionGuard: resolveVar returned null for key segment", ['key' => $key, 'segment' => $segments[$i]]);
                return null;
            }
        }

        if (is_scalar($value) || is_null($value)) {
            Log::info("PermissionGuard: resolveVar returning scalar value", ['key' => $key, 'value' => $value]);
            return $value;
        }

        Log::warning("PermissionGuard: resolveVar resolved to non-scalar (ignored in expression)", [
            'key' => $key,
            'resolved_type' => gettype($value)
        ]);

        return null;
    }

    /**
     * Assign a variable value in the nested variables array.
     */
    protected static function assignVariable($key, $value)
    {
        Log::info("PermissionGuard: Assigning variable", ['key' => $key, 'value' => $value]);

        $segments = explode('.', $key);
        $ref = &self::$variables;

        foreach ($segments as $segment) {
            if (!isset($ref[$segment])) {
                $ref[$segment] = [];
            }
            $ref = &$ref[$segment];
        }

        $ref = $value;
        Log::info("PermissionGuard: Variable assigned", ['key' => $key]);
    }

    /**
     * Helper to get variable from route or input.
     */
    protected static function getVarFromPathOrInput($key)
    {
        $requestPath = '/' . ltrim(request()->path(), '/');
        $urls = self::$config['urls'] ?? [];

        Log::info("PermissionGuard: Starting getVarFromPathOrInput", ['key' => $key, 'requestPath' => $requestPath]);

        // 1. Verifica se já existe em self::$variables['input']
        if (isset(self::$variables['input'][$key])) {
            Log::info("PermissionGuard: Found in variables.input", [
                'key' => $key,
                'value' => self::$variables['input'][$key]
            ]);
            return self::$variables['input'][$key];
        }

        // 2. Tenta extrair a partir da rota
        foreach ($urls as $route => $config) {
            if (!str_contains($route, '$' . $key)) {
                continue;
            }

            [$methodPart, $configPathQuery] = explode(' ', $route, 2);
            $configPath = explode('?', $configPathQuery)[0];

            $configSegments = explode('/', trim($configPath, '/'));
            $requestSegments = explode('/', trim($requestPath, '/'));

            if (count($configSegments) !== count($requestSegments)) {
                continue;
            }

            Log::info("PermissionGuard: Comparing segments", [
                'configSegments' => $configSegments,
                'requestSegments' => $requestSegments
            ]);

            foreach ($configSegments as $i => $segment) {
                if (str_starts_with($segment, '$')) {
                    $varName = substr($segment, 1);
                    $value = $requestSegments[$i];
                    self::$variables['input'][$varName] = $value;

                    Log::info("PermissionGuard: Matched variable from path", [
                        'var' => $varName,
                        'value' => $value
                    ]);

                    if ($varName === $key) {
                        return $value;
                    }
                }
            }
        }

        // 3. Fallback para query string ou request input
        $value = request()->query($key) ?? request()->input($key);
        Log::info("PermissionGuard: Fallback to query/input", ['key' => $key, 'value' => $value]);
        return $value;
    }
}
