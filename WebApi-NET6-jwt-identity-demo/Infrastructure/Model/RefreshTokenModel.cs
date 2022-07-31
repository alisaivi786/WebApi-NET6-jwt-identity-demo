namespace WebApi_NET6_jwt_identity_demo.Infrastructure.Model
{
    public class RefreshTokenModel
    {
        public string? Token { get; set; }
        public DateTime Created { get; set; }
        public DateTime Expires { get; set; }
        public string? UserName { get; set; }
    }
}
