<?php

namespace Lfffd\SecurityMiddleware;

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
                self::parseVariable($var, $parser);
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

        Log::info("PermissionGuard: Starting matchUrlConfig", ['path' => $path, 'method' => $method]);

        foreach ($config as $url => $methods) {
            Log::info("PermissionGuard: Checking configured URL", ['url' => $url]);

            // Step 1: Replace $variables by placeholder
            $placeholder = '___VAR___';
            $temp = preg_replace('/\$[a-zA-Z0-9_]+/', $placeholder, $url);
            Log::info("PermissionGuard: After replacing variables with placeholder", ['temp' => $temp]);

            // Step 2: Escape the rest of the URL
            $escaped = preg_quote($temp, '/');
            Log::info("PermissionGuard: After escaping special characters", ['escaped' => $escaped]);

            // Step 3: Replace placeholder with regex pattern
            $pattern = str_replace($placeholder, '[^/]+', $escaped);
            Log::info("PermissionGuard: Final regex pattern for matching", ['pattern' => $pattern]);

            if (preg_match("~^$pattern$~", $path)) {
                Log::info("PermissionGuard: URL matched regex pattern", ['matched_url' => $url, 'pattern' => $pattern]);

                // Normalize to arrays
                $methodConfig = isset($methods[$method]) && is_array($methods[$method]) ? $methods[$method] : [];
                $starConfig = isset($methods['*']) && is_array($methods['*']) ? $methods['*'] : [];

                // Merge '*' config into method config
                $mergedRules = array_merge_recursive($starConfig, $methodConfig);

                Log::info("PermissionGuard: Found rules for method", ['method' => $method, 'rules' => $mergedRules]);
                Log::info("PermissionGuard: Returning matched rules");

                return $mergedRules;
            } else {
                Log::info("PermissionGuard: URL did not match regex pattern", ['pattern' => $pattern]);
            }
        }

        Log::info("PermissionGuard: No URL matched the requested path");
        Log::info("PermissionGuard: Returning null from matchUrlConfig");
        return null;
    }

    /**
     * Parse a variable based on the parser string.
     */
    protected static function parseVariable($key, $parser)
    {
        Log::info("PermissionGuard: parseVariable called", ['key' => $key, 'parser' => $parser]);

        if (is_string($parser)) {
            if (str_starts_with($parser, 'php:')) {
                $code = substr($parser, 4);
                Log::info("PermissionGuard: Parsing PHP code", ['code' => $code]);
                self::assignVariable($key, eval("return $code;"));
            } elseif (str_starts_with($parser, 'model:')) {
                $modelExpr = trim(substr($parser, 6));
                Log::info("PermissionGuard: Parsing model expression", ['expression' => $modelExpr]);
                if (!str_contains($modelExpr, '::')) {
                    $modelClass = "App\\Models\\" . $modelExpr;
                    $id = self::getVarFromPathOrInput('id');
                    Log::info("PermissionGuard: Finding model by id", ['model' => $modelClass, 'id' => $id]);
                    self::assignVariable($key, $modelClass::find($id));
                } else {
                    Log::info("PermissionGuard: Evaluating full model expression");
                    self::assignVariable($key, eval("return $modelExpr;"));
                }
            }
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

        // Add quotes around barewords that aren't variables/literals
        $parsedExpr = preg_replace_callback('/\b([a-zA-Z_][a-zA-Z0-9_]*)\b/', function($matches) {
            $word = $matches[1];
            if (in_array(strtolower($word), ['null', 'true', 'false']) || is_numeric($word)) {
                return $word;
            }
            if (str_starts_with($word, '$')) {
                return $word;
            }
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
            return $val ?? 'null';
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

        Log::info("PermissionGuard: resolveVar returning value", ['key' => $key, 'value' => $value]);
        return $value;
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
        $value = request()->route($key) ?? request()->input($key);
        Log::info("PermissionGuard: getVarFromPathOrInput", ['key' => $key, 'value' => $value]);
        return $value;
    }
}
