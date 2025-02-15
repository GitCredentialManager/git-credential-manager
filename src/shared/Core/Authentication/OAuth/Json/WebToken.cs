using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GitCredentialManager.Authentication.Oauth.Json
{
    public class WebToken(WebToken.TokenHeader header, WebToken.TokenPayload payload, string signature)
    {
        public class TokenHeader
        {
            [JsonRequired]
            [JsonPropertyName("typ")]
            public string Type { get; set; }
        }
        public class TokenPayload
        {
            [JsonRequired]
            [JsonPropertyName("exp")]
            public long Expiry { get; set; }
        }
        public TokenHeader Header { get; } = header;
        public TokenPayload Payload { get; } = payload;
        public string Signature { get; } = signature;

        static public WebToken TryCreate(string value)
        {
            try
            {
                var parts = value.Split('.');
                if (parts.Length != 3)
                {
                    return null;
                }
                var header = JsonSerializer.Deserialize<TokenHeader>(Base64UrlConvert.Decode(parts[0]));
                var payload = JsonSerializer.Deserialize<TokenPayload>(Base64UrlConvert.Decode(parts[1]));
                return new WebToken(header, payload, parts[2]);
            }
            catch
            {
                return null;
            }

        }

        static public bool IsExpiredToken(string value)
        {
            var token = TryCreate(value);
            return token != null && token.Payload.Expiry < DateTimeOffset.Now.ToUnixTimeSeconds();

        }
    }
}
