using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WebApi_NET6_jwt_identity_demo.Migrations
{
    public partial class addRefreshTokenTable : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "RefreshToken",
                columns: table => new
                {
                    Token = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Created = table.Column<DateTime>(type: "datetime", nullable: false),
                    Expires = table.Column<DateTime>(type: "datetime", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RefreshToken", x => x.Token);
                });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RefreshToken");
        }
    }
}
