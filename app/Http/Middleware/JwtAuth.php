<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;
use PHPOpenSourceSaver\JWTAuth\Exceptions\TokenExpiredException;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth as FacadesJWTAuth;

class JwtAuth
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next)
    {
        Log::info('JwtAuth middleware invoked.');

        // Extract token from the Authorization header
        $token = $request->header('Authorization');

        // Check if the token is present and formatted correctly

        if (!$token || !str_starts_with($token, 'Bearer ')) {
            return response()->json([
                'error' => 'Unauthorized',
                'message' => 'Bearer token not found',
            ], 401);
        }

        // Remove 'Bearer ' prefix
        $token = str_replace('Bearer ', '', $token);

        // Validate token and set user
        $user = $this->validateToken($token);

        if (!$user instanceof Authenticatable) {
            return response()->json([
                'error' => 'Unauthorized',
                'message' => $user,
            ], 401);
        }

        // Set the authenticated user
        auth()->setUser($user);

        return $next($request);
    }

    protected function validateToken($token): Authenticatable | string
    {
        try {
            $user = FacadesJWTAuth::parseToken($token)->authenticate();


            // Ensure the user implements Authenticatable
            if ($user instanceof Authenticatable) {
                return $user;
            }

            return "User not found";
        } catch (TokenExpiredException $e) {
            // Handle token expiration
            Log::error('Token expired: ' . $e->getMessage());

            // You can return a specific response for expired tokens
            return 'Token expired';
        } catch (JWTException $e) {
            Log::error('Token validation error: ' . $e->getMessage());
            return 'Token validation error: ' . $e->getMessage();
        }
    }
}
