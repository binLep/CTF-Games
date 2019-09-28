Authors: Sin\_\_, DarkyAngel

This challenge should prove very interesting:

    the configuration consists of a vanilla Mellivora install from the repo (commit 0a7181250972715fe7d391bbd538eeba16a80356)
    the flag is the same as the flag for the only challenge added on Mellivora, which you need to obtain
    the initial setup is backed up and restored every hour
    the challenge is solvable because the platform is exploitable
    if you've found an exploitable bug but require some resources that might not be available on short notice due to the limited duration of the CTF, let the author know as we also have something prepared for this situation. Note that resources we will (obviously) not provide include: VPSes, CPU time, etc
    the instance is running in an Alpine Linux docker environment with the following environment variables:

```bash
      MELLIVORA_CONFIG_DB_ENGINE: mysql
      MELLIVORA_CONFIG_DB_HOST: db
      MELLIVORA_CONFIG_DB_PORT: 3306
      MELLIVORA_CONFIG_DB_NAME: ******
      MELLIVORA_CONFIG_DB_USER: ******
      MELLIVORA_CONFIG_DB_PASSWORD: ******
      MELLIVORA_CONFIG_RECAPTCHA_ENABLE_PUBLIC: 'true'
      MELLIVORA_CONFIG_RECAPTCHA_PUBLIC_KEY: *****
      MELLIVORA_CONFIG_RECAPTCHA_PRIVATE_KEY: *****
      MELLIVORA_CONFIG_SITE_URL: http://52.157.103.137:13370/
      MELLIVORA_CONFIG_SITE_URL_STATIC_RESOURCES: http://52.157.103.137:13370/
```

Note that we didn't add a mail server to prevent spamming so you might see a few exceptions here and there.

We have also made a setup modification that prevents defacing (your exploit will work unmodified; it does not make the exploit any easier or any harder)

Go for it: http://52.157.103.137:13370/scores