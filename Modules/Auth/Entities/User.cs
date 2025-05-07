namespace ModularERP.Modules.Auth.Entities 
{
    public class User
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string FullName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public bool IsActive { get; set; } = true;
        public string Role { get; set; } = "User"; // Default role
        public DateTime? LastLoginAt { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime LastUpdatedAt {get; set; } = DateTime.UtcNow;
    }
}