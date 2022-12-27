# Conditional cookie authenticator

## Build

```
mvn clean install
```

## Deployment

Copy generated JAR in deployment directory

## Usage

![](2022-12-27-13-10-56.png)

This conditional authenticator allows an authentication flow that asks an already authenticated user for a secret such as a password, OTP or webauthn key.