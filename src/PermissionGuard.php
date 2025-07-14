<?php

namespace SecurityMiddleware;

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

    public static function init(string $yamlFilePath, array $variables = [], string $bladeError = null): void
    {
        if ($bladeError) {
            self::$bladeError = $bladeError;
        }

        self::$variables = $variables;

        if (Cache::has('security_config')) {
            self::$config = Cache::get('security_config');
        } else {
            $yamlContent = file_get_contents($yamlFilePath);
            self::$config = Spyc::YAMLLoadString($yamlContent);
            Cache::put('security_config', self::$config, 3600);
        }
    }

    public static function handleRequest($request)
    {
        $path = '/' . ltrim($request->path(), '/');
        $method = strtoupper($request->method());

        $rulesConfig = self::matchUrlConfig($path, $method);

        if (!$rulesConfig) {
            return response()->view(self::$bladeError, ['message' => "Unauthorized URL: $path"], 403);
        }

        // Execute parsers
        if (!empty($rulesConfig['parsers'])) {
            foreach ($rulesConfig['parsers'] as $var => $parser) {
                self::parseVariable($var, $parser);
            }
        }

        // Evaluate rules
        if (!empty($rulesConfig['rules'])) {
            foreach ($rulesConfig['rules'] as $ruleName => $rule) {
                if (!self::evaluateRule($rule)) {
                    $message = self::parseMessage($rule['message'] ?? "Rule $ruleName failed.");
                    return response()->view(self::$bladeError, ['message' => $message], 403);
                }
            }
        }

        return null;
    }

    public static function middleware(string $yamlPath, array $vars = [], string $bladeError = null)
    {
        return function ($request, Closure $next) use ($yamlPath, $vars, $bladeError) {
            self::init($yamlPath, $vars, $bladeError);
            $response = self::handleRequest($request);
            return $response ?? $next($request);
        };
    }

    protected static function matchUrlConfig($path, $method)
    {
        $config = self::$config['urls'] ?? [];

        foreach ($config as $url => $methods) {
            $pattern = preg_replace('/\\$[a-zA-Z0-9_]+/', '[^/]+', preg_quote($url, '/'));
            if (preg_match("/^$pattern$/", $path)) {
                return $methods[$method] ?? $methods['*'] ?? null;
            }
        }

        return null;
    }

    protected static function parseVariable($key, $parser)
    {
        if (is_string($parser)) {
            if (str_starts_with($parser, 'php:')) {
                $code = substr($parser, 4);
                self::assignVariable($key, eval("return $code;"));
            } elseif (str_starts_with($parser, 'model:')) {
                $modelExpr = trim(substr($parser, 6));
                if (!str_contains($modelExpr, '::')) {
                    $modelClass = "App\\Models\\" . $modelExpr;
                    $id = self::getVarFromPathOrInput('id');
                    self::assignVariable($key, $modelClass::find($id));
                } else {
                    self::assignVariable($key, eval("return $modelExpr;"));
                }
            }
        }
    }

    protected static function evaluateRule(array $rule): bool
    {
        $expr = $rule['permission'] ?? $rule['permissions'] ?? null;
        if (!$expr) return false;

        $parsedExpr = self::interpolateVars($expr);

        try {
            return eval("return ($parsedExpr);");
        } catch (\Throwable $e) {
            Log::error('PermissionGuard evaluation error: ' . $e->getMessage());
            return false;
        }
    }

    protected static function parseMessage($message)
    {
        return self::interpolateVars($message);
    }

    protected static function interpolateVars($text)
    {
        return preg_replace_callback('/\\$([a-zA-Z0-9_\.]+)/', function ($matches) {
            return self::resolveVar($matches[1]) ?? 'null';
        }, $text);
    }

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
                return null;
            }
        }

        return $value;
    }

    protected static function assignVariable($key, $value)
    {
        $segments = explode('.', $key);
        $ref = &self::$variables;

        foreach ($segments as $segment) {
            if (!isset($ref[$segment])) {
                $ref[$segment] = [];
            }
            $ref = &$ref[$segment];
        }

        $ref = $value;
    }

    protected static function getVarFromPathOrInput($key)
    {
        return request()->route($key) ?? request()->input($key);
    }
}
