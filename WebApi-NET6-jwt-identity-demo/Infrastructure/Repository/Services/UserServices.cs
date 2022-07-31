using WebApi_NET6_jwt_identity_demo.Infrastructure.Entities;
using WebApi_NET6_jwt_identity_demo.Infrastructure.Repository.IServices;

namespace WebApi_NET6_jwt_identity_demo.Infrastructure.Repository.Services
{
    public class UserServices : IUserServices
    {

        public static RefreshToken? Token;

        public bool CreateRefreshToken(RefreshToken refreshToken)
        {
            // Save Data into Database....
            Token = refreshToken;
            return true;
        }

        public RefreshToken GetRefreshToken(string? token)
        {
            // Get Data from Database....
            if (Token != null)
            {
                if(Token.Token == token)
                {
                    return Token;
                }
                else
                {
                    return new RefreshToken();
                }
            }
            else
            {
                return new RefreshToken();
            }
        }
    }
}
