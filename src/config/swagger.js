export default {
  openapi: "3.1.0",
  info: {
    title: "Authentication API",
    version: "1.0.0",
    description: "API documentation for auth routes (local and OAuth)",
  },
  servers: [
    {
      url: "http://localhost:4000/api/v1",
      description: "Local dev server",
    },
  ],
  paths: {
    "/auth/register": {
      post: {
        summary: "Register new user",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  name: { type: "string" },
                  email: { type: "string" },
                  password: { type: "string" },
                },
                required: ["name", "email", "password"],
              },
            },
          },
        },
        responses: {
          "201": { description: "User registered successfully" },
        },
      },
    },
    "/auth/verifyEmail/{token}": {
      get: {
        summary: "Verify user email",
        parameters: [
          {
            name: "token",
            in: "path",
            required: true,
            schema: { type: "string" },
          },
        ],
        responses: {
          "200": { description: "Email verified successfully" },
        },
      },
    },
    "/auth/login": {
      post: {
        summary: "Login with email and password",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  email: { type: "string" },
                  password: { type: "string" },
                },
                required: ["email", "password"],
              },
            },
          },
        },
        responses: {
          "200": { description: "Login successful" },
        },
      },
    },
    "/auth/profile": {
      get: {
        summary: "Get user profile",
        security: [{ cookieAuth: [] }],
        responses: {
          "200": { description: "User profile returned" },
          "401": { description: "Unauthorized" },
        },
      },
    },
    "/auth/logout": {
      get: {
        summary: "Logout user",
        security: [{ cookieAuth: [] }],
        responses: {
          "200": { description: "Logged out successfully" },
        },
      },
    },
    "/auth/forgot-password": {
      post: {
        summary: "Send reset password link",
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  email: { type: "string" },
                },
                required: ["email"],
              },
            },
          },
        },
        responses: {
          "200": { description: "Reset email sent" },
        },
      },
    },
    "/auth/reset-password/{token}": {
      post: {
        summary: "Reset password with token",
        parameters: [
          {
            name: "token",
            in: "path",
            required: true,
            schema: { type: "string" },
          },
        ],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  newPassword: { type: "string" },
                  confirmPassword: { type: "string" },
                },
                required: ["newPassword", "confirmPassword"],
              },
            },
          },
        },
        responses: {
          "200": { description: "Password reset successfully" },
        },
      },
    },
    "/auth/google": {
      get: {
        summary: "Start Google OAuth login",
        description: "Redirects the user to Google's OAuth 2.0 login page. This flow cannot be tested from Swagger UI.",
        responses: {
          "302": { description: "Redirect to Google OAuth 2.0" },
        },
      },
    },
    "/auth/google/callback": {
      get: {
        summary: "Google OAuth callback",
        responses: {
          "200": { description: "Google login success or failure" },
        },
      },
    },
    "/auth/github": {
      get: {
        summary: "Start GitHub OAuth",
        description: "Redirects the user to Githubs's OAuth 2.0 login page. This flow cannot be tested from Swagger UI.",
        responses: {
          "302": { description: "Redirect to GitHub" },
        },
      },
    },
    "/auth/github/callback": {
      get: {
        summary: "GitHub OAuth callback",
        responses: {
          "200": { description: "GitHub login success or failure" },
        },
      },
    },
  },
  components: {
    securitySchemes: {
      cookieAuth: {
        type: "apiKey",
        in: "cookie",
        name: "accessToken",
      },
    },
  },
};
