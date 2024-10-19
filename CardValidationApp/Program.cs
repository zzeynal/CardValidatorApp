using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Dynamic;

namespace CardValidationApp
{
    class Program
    {
        // Use the provided Key Id and Shared Key for authorization
        private static readonly string baseUrl = "https://acstopay.online";
        private static readonly string apiKey = "47e8fde35b164e888a57b6ff27ec020f";
        private static readonly string sharedKey = "ac/1LUdrbivclAeP67iDKX2gPTTNmP0DQdF+0LBcPE/3NWwUqm62u5g6u+GE8uev5w/VMowYXN8ZM+gWPdOuzg==";

        static async Task Main(string[] args)
        {
            //1. Ask for Card number from Console
            Console.WriteLine("Enter card number (PAN):");

            //2. Get Card number from Console
            string cardNumber = Console.ReadLine();

            //3. Validate Card number
            string validationResult = await ValidateCardAsync(cardNumber);
            
            //4. Process the response
            Console.WriteLine(validationResult);
        }

        public class CardInfo
        {
            public string Pan { get; set; }
        }

        // Response class to map API response
        public class ApiResponse
        {
            public string Id { get; set; } // Use string for Id if it's returned as a string in JSON
            public CardInfo CardInfo { get; set; }
            public string Status { get; set; }
        }


        static async Task<string> ValidateCardAsync(string pan)
        {
            //string endpoint = $"{baseUrl}/api/testassignments/pan";
            var cardInfo = new
            {
                CardInfo = new CardInfo
                {
                    Pan = pan
                }
            };

            //JSONify Payload
            string jsonPayload = JsonConvert.SerializeObject(cardInfo);

            //Create JWS Token based on Payload
            string jwsToken = CreateJwsToken(jsonPayload);

            //Make a Post request to the API Server
            return await SendPostRequest(jwsToken);
        }

        //Create JWS token
        static string CreateJwsToken(string jsonPayload)
        {
            // Create the JWS Header
            var header = new
            {
                alg = "HS256",
                kid = apiKey,
                signdate = DateTime.UtcNow.ToString("o"), // Use current timestamp in ISO 8601 format
                cty = "application/json"
            };
            string jsonHeader = JsonConvert.SerializeObject(header);

            // Encode header and payload in Base64 URL format
            string encodedHeader = Base64UrlEncode(Encoding.UTF8.GetBytes(jsonHeader));
            string encodedPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(jsonPayload));

            // Sign the request
            string messageToSign = $"{encodedHeader}.{encodedPayload}";
            string signature = CreateSignature(messageToSign, sharedKey);

            // Return the JWS token
            return $"{messageToSign}.{signature}";
        }

        static async Task<string> SendPostRequest(string jwsToken)
        {
            using (HttpClient client = new HttpClient())
            {
                client.BaseAddress = new Uri(baseUrl);

                // Send the JWS token in the request body
                var content = new StringContent(jwsToken, Encoding.UTF8, "application/json");
                HttpResponseMessage response = await client.PostAsync("/api/testassignments/pan", content);

                if (response.IsSuccessStatusCode)
                {
                    //
                    string jsonResponse = await response.Content.ReadAsStringAsync();

                    // Now we decode the JWS token payload
                    ApiResponse decodedResponse =  DecodeAndMapJwsToken(jsonResponse);
                    // Return "Successfully" or "Unsuccessfully" based on the API response
                    return decodedResponse.Status == "Success" ? "Successfully" : "Unsuccessfully";
                }
                else
                {
                    // Handle errors
                    string errorResponse = await response.Content.ReadAsStringAsync();
                    return $"Error: {errorResponse}";
                }
            }
        }

        // Decodes the JWS token, extracts the payload, and deserializes it into ApiResponse
        static ApiResponse DecodeAndMapJwsToken(string jwsToken)
        {
            // Split the JWS token into its three parts
            string[] tokenParts = jwsToken.Split('.');
            if (tokenParts.Length == 3)
            {
                // The payload is the second part (Base64 URL encoded)
                string payload = Base64UrlDecode(tokenParts[1]);

                // Deserialize the payload to ApiResponse
                var result = JsonConvert.DeserializeObject<ApiResponse>(payload);

                return result;
            }
            else
            {
                throw new Exception("Invalid JWS Token format.");
            }
        }

        // Helper function to Base64 URL decode the payload
        static string Base64UrlDecode(string input)
        {
            string base64 = input.Replace('-', '+').Replace('_', '/');
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }
            byte[] byteArray = Convert.FromBase64String(base64);
            return Encoding.UTF8.GetString(byteArray);
        }

        // Helper function for Base64 URL encoding
        static string Base64UrlEncode(byte[] input)
        {
            return Convert.ToBase64String(input)
                .TrimEnd('=')         // Remove padding
                .Replace('+', '-')    // Replace '+' with '-'
                .Replace('/', '_');   // Replace '/' with '_'
        }

        // Helper function to create the HMACSHA256 signature
        static string CreateSignature(string message, string secret)
        {
            var key = Convert.FromBase64String(secret.Replace("\r", "").Replace("\n", "").Replace(" ", ""));
            using (var hmac = new HMACSHA256(key))
            {
                var signatureBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
                return Base64UrlEncode(signatureBytes);
            }
        }
    }
}
