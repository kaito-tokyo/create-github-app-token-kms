import type { AppAuthentication, State } from "./types.js";

import { KMSClient, SignCommand } from "@aws-sdk/client-kms";

function encodeBase64URL(buffer) {
  return buffer.toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll('"', "");
}

async function signJWTWithKMS(authOptions) {
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 600;

  const header = {
    alg: "RS256",
    typ: "JWT"
  };
  
  const payload = {
    iat,
    exp,
    iss: authOptions.id,
  };

  const headerB64 = encodeBase64URL(Buffer.from(JSON.stringify(header)));
  const payloadB64 = encodeBase64URL(Buffer.from(JSON.stringify(payload)));
  const contentString = `${headerB64}.${payloadB64}`
  const contentBytes = Buffer.from(contentString);

  const { privateKey } = authOptions;
  if (privateKey.startsWith("awskms:")) {
    const json = privateKey.replace(/^awskms:/, "");
    const {
      region,
      keyId: KeyId,
    } = JSON.parse(json);

    const client = new KMSClient({ region });
    const command = new SignCommand({
      KeyId,
      Message: contentBytes,
      MessageType: "RAW",
      SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256"
    })
    const response = await client.send(command);
    const signature2B64 = encodeBase64URL(Buffer.from(response.Signature));
    const token = `${headerB64}.${payloadB64}.${signature2B64}`;
    return {
      appId: authOptions.id,
      expiration: exp,
      token
    };
  } else {
    throw new Error("Not implemented!");
  }
}

export async function getAppAuthentication({
  appId,
  privateKey,
  timeDifference,
}: State & {
  timeDifference?: number | undefined;
}): Promise<AppAuthentication> {
  try {
    const authOptions = {
      id: appId,
      privateKey,
    };

    if (timeDifference) {
      Object.assign(authOptions, {
        now: Math.floor(Date.now() / 1000) + timeDifference,
      });
    }

    const appAuthentication = await signJWTWithKMS(authOptions);

    return {
      type: "app",
      token: appAuthentication.token,
      appId: appAuthentication.appId,
      expiresAt: new Date(appAuthentication.expiration * 1000).toISOString(),
    };
  } catch (error) {
    if (privateKey === "-----BEGIN RSA PRIVATE KEY-----") {
      throw new Error(
        "The 'privateKey` option contains only the first line '-----BEGIN RSA PRIVATE KEY-----'. If you are setting it using a `.env` file, make sure it is set on a single line with newlines replaced by '\n'",
      );
    } else {
      throw error;
    }
  }
}
