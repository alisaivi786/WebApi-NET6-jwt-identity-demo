using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace WebApi_NET6_jwt_identity_demo.Infrastructure.Entities
{
    [Table("RefreshToken")]
    public class RefreshToken
    {
        [Key]
        public string? Token { get; set; }
        public DateTime Created { get; set; } = DateTime.Now;
        public DateTime Expires { get; set; }
        public string? UserName { get; set; }
    }
}
