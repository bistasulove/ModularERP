using Microsoft.Extensions.Logging;
using System;

namespace ModularERP.Common.Logging
{
    public static class LoggingExtensions
    {
        // Security related logs
        public static void LogSecurityEvent(this ILogger logger, string eventType, string userId, string details)
        {
            logger.LogInformation("SECURITY EVENT: {EventType} | User: {UserId} | Details: {Details}", 
                eventType, userId, details);
        }
        
        public static void LogAuthenticationSuccess(this ILogger logger, string userId, string email)
        {
            logger.LogInformation("Authentication succeeded for user {UserId}, {Email}", userId, email);
        }
        
        public static void LogAuthenticationFailure(this ILogger logger, string email, string reason)
        {
            logger.LogWarning("Authentication failed for {Email}. Reason: {Reason}", email, reason);
        }
        
        // Data access logs
        public static void LogDataAccess(this ILogger logger, string operation, string entity, string userId, string details)
        {
            logger.LogInformation("DATA ACCESS: {Operation} | Entity: {Entity} | User: {UserId} | Details: {Details}", 
                operation, entity, userId, details);
        }
        
        // Performance logs
        public static IDisposable BeginTimedOperation(this ILogger logger, string operationName)
        {
            return new TimedLogOperation(logger, operationName);
        }
        
        private class TimedLogOperation : IDisposable
        {
            private readonly ILogger _logger;
            private readonly string _operationName;
            private readonly DateTime _startTime;
            
            public TimedLogOperation(ILogger logger, string operationName)
            {
                _logger = logger;
                _operationName = operationName;
                _startTime = DateTime.UtcNow;
                
                _logger.LogDebug("Operation {OperationName} started", operationName);
            }
            
            public void Dispose()
            {
                var elapsed = DateTime.UtcNow - _startTime;
                _logger.LogInformation("Operation {OperationName} completed in {ElapsedMilliseconds}ms", 
                    _operationName, elapsed.TotalMilliseconds);
            }
        }
    }
} 