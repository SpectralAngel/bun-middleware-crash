declare namespace NodeJS {
  interface ProcessEnv {
    AUTH_CALLBACK_URL: string;
    AUTH_KEYCLOAK_ID: string;
    AUTH_KEYCLOAK_SECRET: string;
    AUTH_KEYCLOAK_ISSUER: string;
    AUTH_SECRET: string;
  }
}
