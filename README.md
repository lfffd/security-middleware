
# Laravel Security Middleware

This package provides a powerful security middleware for Laravel applications, allowing you to define access control rules using a YAML configuration file. The middleware supports dynamic permissions, model lookups, function evaluations, and parameter sanitization with customizable Blade error views.

## 🚀 Features

- ✅ Define rules for each URL and HTTP method using YAML
- ✅ Support for variable substitution using dot notation (e.g., `$user.role`)
- ✅ Run parsers to dynamically fetch models or compute values
- ✅ Use inline PHP code or custom functions
- ✅ Cache rules for performance
- ✅ Show a Blade error view when access is denied

## 📦 Installation

```bash
composer require your-vendor/security-middleware
```

If using Laravel < 5.5, manually register the service provider in `config/app.php`:

```php
'providers' => [
    SecurityMiddleware\PermissionGuardServiceProvider::class,
],
```

## ⚙️ Configuration

1. Create a YAML file to define access rules (e.g. `routes/security-rules.yaml`).
2. Include rules per URL and HTTP method. You can define `parsers` and `rules`.

### 🔧 Sample YAML
```yaml
functions:
  ballotIsOpen:
    class: App\Classes\Ballots\Ballot
    method: isOpen

urls:
  /users/list:
    GET:
      rules:
        only_admin:
          permission: $user.role == admin
          message: Only admins are allowed

  /users/edit/$id:
    *:
      parsers:
        user:
          calculation: model:User
        input.id:
          set: php:trim($input.id)

      rules:
        valid_id:
          calculation: php:is_numeric($input.id)
          message: ID must be numeric.
        tenant_match:
          permission: $user.tenant == $userProperties.tenant
          message: You do not have permission to edit this user.
```

## 🧩 Usage

Add the middleware globally or to specific routes:

### Option 1: Global Middleware (recommended)
```php
// app/Http/Kernel.php
use SecurityMiddleware\PermissionGuard;

protected $middlewareGroups = [
    'web' => [
        // ...
        PermissionGuard::middleware(
            base_path('routes/security-rules.yaml'),
            [
                'user' => auth()->user(),
                'input' => request()->all()
            ],
            'errors.unauthorized'
        )
    ],
];
```

### Option 2: Route Middleware
```php
Route::middleware([
    PermissionGuard::middleware(
        base_path('routes/security-rules.yaml'),
        ['user' => auth()->user()],
        'errors.unauthorized'
    )
])->group(function () {
    Route::get('/users/list', 'UserController@index');
});
```

## 🔒 Writing Rules
- Use `$user`, `$input`, or any custom variable passed to the middleware.
- Use model lookups: `model:User`, `model:User.email = $input.email`
- Call PHP directly: `php:trim($input.id)`
- Chain complex expressions across multiple rules

## ✅ composer.json
```json
{
  "name": "your-vendor/security-middleware",
  "description": "YAML-based dynamic permission middleware for Laravel",
  "type": "library",
  "license": "MIT",
  "autoload": {
    "psr-4": {
      "SecurityMiddleware\\": "src/"
    }
  },
  "require": {
    "illuminate/support": "^8.0|^9.0|^10.0",
    "mustangostang/spyc": "^0.6"
  },
  "extra": {
    "laravel": {
      "providers": [
        "SecurityMiddleware\\PermissionGuardServiceProvider"
      ]
    }
  }
}
```

## 🧪 Example Feature Test
```php
public function testUnauthorizedUserCannotAccessList()
{
    $response = $this->actingAs(User::factory()->create(['role' => 'guest']))
                     ->get('/users/list');

    $response->assertStatus(403);
    $response->assertSee('Only admins are allowed');
}

public function testAdminCanAccessList()
{
    $admin = User::factory()->create(['role' => 'admin']);

    $response = $this->actingAs($admin)->get('/users/list');
    $response->assertStatus(200);
}
```

## 📄 License
MIT License
