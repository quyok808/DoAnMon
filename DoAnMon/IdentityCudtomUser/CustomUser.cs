﻿using Microsoft.AspNetCore.Identity;

namespace DoAnMon.IdentityCudtomUser
{
    public class CustomUser : IdentityUser
    {
        public string? Mssv { get; set; }
        public string? Name { get; set; }
    }
}
