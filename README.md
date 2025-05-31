🔐 WebBasedCrypto
-

A secure full-stack web application for encrypted messaging, built with Spring Boot and React.js. It offers symmetric encryption, secure key exchange, JWT-based authentication, and OTP verification, ensuring confidential communication between users.

🚀 Features
-

🔑 OTP Verification: Email-based OTP during user registration for enhanced security.

🛡️ JWT Authentication: Secure login with access and refresh tokens.

♻️ Token Refresh: Endpoint to refresh tokens with auto-blacklisting of expired ones.

🚪 Secure Logout: Invalidates tokens and clears security context.

👥 Role-Based Access Control: Fine-grained access using annotations.

📧 SMTP Integration: For sending OTPs via email.

🗃️ Redis Integration: Handles session and token management.

🧱 Symmetric Encryption: Secure message encryption and decryption.

🖥️ React Frontend: Protected routes, toast notifications, and authentication context.

⚡ Real-time Messaging: Instant message delivery and status updates via Server-Sent Events (SSE) and Redis Pub/Sub.

🛠️ Tech Stack
-
| Layer       | Technology                  |
| ----------- | --------------------------- |
| Backend     | Spring Boot 3.x             |
| Auth        | Spring Security, JWT (jjwt) |
| Data Store  | MySQL                       |
| Token Store | Redis (Dockerized)          |
| Email       | Jakarta Mail (SMTP)         |
| Build Tool  | Maven                       |
| Java        | Java 17+                    |
| Frontend    | React.js, Tailwind CSS      |
| Routing     | react-router-dom            |
| Notification| react-toastify              |
|Real-time    | EventSource Polyfill(https://github.com/EventSource/eventsource/tree/main/src)        |



📦 Prerequisites
-

Java JDK 17+

Maven 3.8+

MySQL (local or Docker)

Docker (for Redis)

Node.js & npm (for frontend)



🐳 Redis Setup with Docker
-

docker run --name redis-crypto -p 6379:6379 -d redis



📧 SMTP Setup for OTP Delivery
-

Update your application.properties:

spring.mail.host=smtp.mail.com
spring.mail.port=587
spring.mail.username=your-email@mail.com
spring.mail.password=your-app-password
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true



⚙️ Core Configuration
-

# Redis Configuration
redis.host=localhost
redis.port=6379

# CORS Configuration
cors.allowed.origins=http://localhost:3000
cors.allowed.methods=GET,POST,PUT,DELETE,PATCH
cors.allowed.headers=*
cors.allowed.credentials=true

🧱 Module Structure
-

Backend: config, filters, security, service, controller, repository, entity, utils

Frontend (React.js):

/pages: Login, Register, Dashboard, ComposeMessage, SentMessages, ProfilePage

/components: Header, Footer, ProtectedRoute, LoadingSpinner, DecryptModal, Sidebar

/context: AuthContext (Manages authentication state and JWTs), SseContext (Manages SSE connection and real-time updates)

App.jsx: Routing setup with conditional footer and toast messages

🔐 Authentication Flow
-

Register: User registers and receives an OTP via email.

OTP Verification: User enters OTP to verify email.

Login: User logs in and receives access & refresh tokens.

Token Validation: JWTs are validated via filters.

Token Refresh: New access token issued using refresh token.

Logout: Tokens are blacklisted via Redis and security context is cleared.

🧾 Token Filters
-

JWTAuthenticationFilter: Handles user login and initial token generation.

JWTValidationFilter: Validates the access token for incoming requests.

JWTRefreshFilter: Manages refresh token logic, issuing new access tokens.

All filters check Redis for blacklisted tokens.

🔒 Role-Based Authorization
-

Use annotations in controllers, for example:

@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/data")
public ResponseEntity<?> getAdminData() {
    // Only accessible by admin role
}

🚀 Production-Ready Practices
-

🔐 HTTPS Support: To be added during deployment.

🔑 Secrets Management: Move DB, mail, JWT secrets to environment variables or a secrets manager.

🔒 Secure Redis: Protect Redis with a password if exposed externally.

🌐 CORS Restrictions: Restrict CORS to production domains.

📊 Logging: Implement SLF4J + Logback for comprehensive logging.

🛡️ Token Revocation: Use Redis TTLs for efficient cleanup of blacklisted tokens.

🌐 React Frontend Highlights
-

AuthContext: Manages authentication state with localStorage persistence.

Protected Routes: Ensures only authenticated users can access certain pages.

Responsive Design: Tailwind CSS for responsive layouts.

Toast Notifications: Provides feedback for login, messages, real-time events.

Conditional Footer: Footer displayed only on the login page.

SseContext: Manages SSE for real-time updates with reconnect and auth.

Dynamic Message Display: Dashboard merges API + SSE messages intelligently.

⚡ Real-time Messaging with SSE & Redis Pub/Sub
-

How it Works:

Client SSE Subscription (SseContext.jsx): React frontend connects to /api/messages/stream after login. Authenticated with JWT. Includes heartbeat and reconnection logic.

Message Sending & Redis Publish (MessageServiceImpl): Backend encrypts, stores, and publishes messages to Redis.

Redis Subscribe & SSE Push (RedisSubscriberImpl): Subscribes to Redis channel and pushes new messages to SSE clients.

Frontend Message Handling (Dashboard.jsx): Merges SSE updates with fetched messages, providing real-time UI updates.

Benefits:
_______________________________________________________
Instantaneity: No delay in delivering new messages.

Efficiency: Persistent SSE reduces server load vs polling.

Scalability: Redis Pub/Sub supports scaling across instances.

Simplified Client Logic: SSE is simpler than WebSockets for one-way comms.

Robustness: Heartbeats, retries, and token refresh built-in.

Key Components in Code:

Backend:
_________________________________________

MessageSseController: SSE stream endpoint

SseEmitterService: Manages emitter lifecycles and sends events

MessageServiceImpl: Encrypts, stores, and publishes message

RedisSubscriberImpl: Listens to Redis and pushes via SSE

Frontend:
___________________________

SseContext.jsx: Manages EventSource, handles events, reconnects

AuthContext.jsx: Provides JWT and refresh logic

Dashboard.jsx: Renders real-time inbox with merged state

✅ Completed Features
-

OTP Registration Flow

Login with JWT

Refresh Token Mechanism

Token Validation Filter

Logout & Token Blacklisting

Redis + SMTP Integration

Real-time Messaging with SSE & Redis Pub/Sub (Full Stack)

CORS Configuration

React Integration with Routing, Auth Context, and Styling

Dynamic UI updates for new messages, read status, and starred status using SSE

Automated SSE reconnection and token refresh handling on the frontend

🧩 To Do (Optional Enhancements)
-

Add Swagger/OpenAPI documentation

Enable HTTPS (during production deployment)

Add monitoring (e.g., Prometheus/Grafana)

Handle persistent login state after page refresh (e.g., "remember me")

File Upload Feature (Encryption during Upload/Decryption during Download)

🧑‍💻 Author
-

Ankit Pandey

LinkedIn: LinkedIn (https://www.linkedin.com/in/ankitpandeyap/)

GitHub: @ankitpandeyap

