using WebApi_NET6_jwt_identity_demo.Infrastructure.Entities;

namespace WebApi_NET6_jwt_identity_demo.Infrastructure.Repository.IServices
{
    public interface IUserServices
    {
        RefreshToken GetRefreshToken(string? token);
        bool CreateRefreshToken(RefreshToken refreshToken);
    }
}
