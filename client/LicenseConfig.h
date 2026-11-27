#pragma once

// Licenc szerver elérése. Élesben állítsd a saját domainedre / IP-dre.
#define LICENSE_SERVER_HOST   L"127.0.0.1"
#define LICENSE_SERVER_PORT   3000
#define LICENSE_SERVER_HTTPS  0            // 1 = HTTPS (ajánlott élesben, pl. reverse proxy mögött)
#define LICENSE_SERVER_PATH   L"/api/verify"

// Login ablak szövegei / mentett kulcs helye (%APPDATA%\<LICENSE_APP_FOLDER>\license.key)
#define LICENSE_APP_TITLE     L"Atrox Roleplay"
#define LICENSE_APP_FOLDER    L"AtroxRoleplay"
