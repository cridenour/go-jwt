JSON Web Token Implementation
=============================

This is a lightweight JSON Web Token (JWT) library written for Go. The goal was to keep the API as simple as possible and follow the spec as closely as we can. 

The library can simply be used with two calls. 

Limitations
-----------
We currently ignore the expiration date on JWT at the library level. As it is part of the payload returned, do with it as you please. 

Example
-------

```go
package main

import (
    "fmt"
    "github.com/cridenour/go-jwt"
)

func main() {
    // Create a mock payload, using map[string]interface{}
    // and the data from the JWT specification
    payload := map[string]interface{}{
		"iss": "joe",
		"exp": 1300819380,
		"http://example.com/is_root": true,
	}

    // Set our key to encode and decode. For RSA encoding
    // and decoding we will use ioutil.ReadFile() and our
    // corresponding private or public key
    key := []byte("ourSuperSecretKey")

    // Call Encode for our default encoder
    token, _ := jwt.Encode(payload, key)

    fmt.Printf("Generated JWT Token: %s\n", token)

    // Decode the token and print out the value for the key "iss"
    decoded := jwt.Decode(token, key)

    fmt.Printf("Key: iss Value: %s\n", decoded["iss"]) 
}
```
