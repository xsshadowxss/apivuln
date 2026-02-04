"""
JWT (JSON Web Token) Vulnerability Detection Module

Detects common JWT implementation flaws including:
- Algorithm confusion (none algorithm)
- Weak secrets
- Expired token acceptance
- Missing signature validation

OWASP API Security Top 10: API2:2023
CWE-347: Improper Verification of Cryptographic Signature
"""

import base64
import json
import time
import hmac
import hashlib
from typing import Optional
from .base import BaseModule, Finding, Severity


class JWTModule(BaseModule):
    """
    Detects JWT-related vulnerabilities.
    """
    
    name = "jwt"
    description = "JWT Vulnerability Detection"
    version = "1.0"
    
    # Common weak secrets to test
    WEAK_SECRETS = [
        "secret",
        "password",
        "123456",
        "jwt_secret",
        "changeme",
        "key",
        "private",
        "supersecret",
        "jwt",
        "token",
    ]
    
    async def run(self, endpoint: dict) -> list[Finding]:
        """
        Test endpoint for JWT vulnerabilities.
        """
        findings = []
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        # Get the JWT token from config
        token = self._extract_jwt()
        
        if not token:
            self.log("No JWT token found in configuration", "warning")
            return findings
        
        self.log(f"Testing JWT vulnerabilities on {path}", "info")
        
        # Parse the token
        decoded = self._decode_jwt(token)
        if not decoded:
            self.log("Failed to decode JWT token", "warning")
            return findings
        
        # Get baseline response
        baseline = await self.requester.send(endpoint)
        
        if not baseline.is_success:
            self.log(f"Baseline request failed: {baseline.status_code}", "warning")
            return findings
        
        # Test 1: None algorithm attack
        none_finding = await self._test_none_algorithm(endpoint, decoded, baseline)
        if none_finding:
            findings.append(none_finding)
        
        # Test 2: Algorithm confusion (alg:none variations)
        alg_findings = await self._test_algorithm_confusion(endpoint, decoded, baseline)
        findings.extend(alg_findings)
        
        # Test 3: Expired token acceptance
        exp_finding = await self._test_expired_token(endpoint, decoded, baseline)
        if exp_finding:
            findings.append(exp_finding)
        
        # Test 4: Weak secret
        weak_finding = await self._test_weak_secrets(endpoint, decoded, baseline)
        if weak_finding:
            findings.append(weak_finding)
        
        # Test 5: Empty signature
        empty_sig_finding = await self._test_empty_signature(endpoint, decoded, baseline)
        if empty_sig_finding:
            findings.append(empty_sig_finding)
        
        return findings
    
    def _extract_jwt(self) -> Optional[str]:
        """Extract JWT from configured auth token."""
        if not self.config or not self.config.auth_token:
            return None
        
        token = self.config.auth_token
        # Remove Bearer prefix if present
        if token.lower().startswith("bearer "):
            token = token[7:]
        
        # Check if it looks like a JWT (3 parts separated by dots)
        if token.count(".") == 2:
            return token
        
        return None
    
    def _decode_jwt(self, token: str) -> Optional[dict]:
        """Decode JWT without verification."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            
            def decode_part(part):
                # Add padding
                padding = 4 - len(part) % 4
                if padding != 4:
                    part += "=" * padding
                decoded = base64.urlsafe_b64decode(part)
                return json.loads(decoded)
            
            return {
                "header": decode_part(parts[0]),
                "payload": decode_part(parts[1]),
                "signature": parts[2],
                "original": token,
            }
        except Exception as e:
            self.log(f"JWT decode error: {e}", "error")
            return None
    
    def _encode_jwt_part(self, data: dict) -> str:
        """Encode a JWT part (header or payload)."""
        json_bytes = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(json_bytes).rstrip(b"=").decode()
    
    def _create_token(self, header: dict, payload: dict, signature: str = "") -> str:
        """Create a JWT token with given parts."""
        header_enc = self._encode_jwt_part(header)
        payload_enc = self._encode_jwt_part(payload)
        return f"{header_enc}.{payload_enc}.{signature}"
    
    def _sign_hs256(self, header: dict, payload: dict, secret: str) -> str:
        """Sign JWT with HS256."""
        header_enc = self._encode_jwt_part(header)
        payload_enc = self._encode_jwt_part(payload)
        message = f"{header_enc}.{payload_enc}".encode()
        signature = hmac.new(secret.encode(), message, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    
    async def _test_none_algorithm(self, endpoint, decoded, baseline) -> Optional[Finding]:
        """Test for 'none' algorithm vulnerability."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        # Create token with alg: none
        header = {"alg": "none", "typ": "JWT"}
        payload = decoded["payload"].copy()
        
        # Create unsigned token
        none_token = self._create_token(header, payload, "")
        
        # Test with the none token
        response = await self.requester.send(
            endpoint,
            extra_headers={self.config.auth_header: f"Bearer {none_token}"}
        )
        
        if response.is_success:
            similarity = self.analyzer.similarity(response, baseline)
            if similarity > 0.5:
                return self.create_finding(
                    severity=Severity.CRITICAL,
                    endpoint=path,
                    method=method,
                    title="JWT 'none' Algorithm Accepted",
                    evidence=(
                        f"Server accepted JWT with alg:none. "
                        f"Response status: {response.status_code}. "
                        f"This allows forging arbitrary tokens without a secret."
                    ),
                    verification=(
                        f"1. Decode your JWT and change header to {{\"alg\":\"none\",\"typ\":\"JWT\"}}\n"
                        f"       2. Remove the signature (third part after second dot)\n"
                        f"       3. Send request with modified token\n"
                        f"       4. Verify access is still granted"
                    ),
                    confidence=95,
                    cwe_id="CWE-347",
                    references=[
                        "https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
                        "https://cwe.mitre.org/data/definitions/347.html",
                    ],
                )
        
        return None
    
    async def _test_algorithm_confusion(self, endpoint, decoded, baseline) -> list[Finding]:
        """Test for algorithm confusion variations."""
        findings = []
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        # Variations of 'none'
        none_variations = ["None", "NONE", "nOnE", "none"]
        
        for alg in none_variations:
            header = {"alg": alg, "typ": "JWT"}
            payload = decoded["payload"].copy()
            token = self._create_token(header, payload, "")
            
            response = await self.requester.send(
                endpoint,
                extra_headers={self.config.auth_header: f"Bearer {token}"}
            )
            
            if response.is_success:
                similarity = self.analyzer.similarity(response, baseline)
                if similarity > 0.5:
                    findings.append(self.create_finding(
                        severity=Severity.CRITICAL,
                        endpoint=path,
                        method=method,
                        title=f"JWT Algorithm '{alg}' Accepted",
                        evidence=(
                            f"Server accepted JWT with alg:{alg}. "
                            f"Response status: {response.status_code}."
                        ),
                        verification=(
                            f"1. Modify JWT header to use alg:{alg}\n"
                            f"       2. Remove signature\n"
                            f"       3. Verify access is granted"
                        ),
                        confidence=95,
                        cwe_id="CWE-347",
                    ))
                    break  # One finding is enough
        
        return findings
    
    async def _test_expired_token(self, endpoint, decoded, baseline) -> Optional[Finding]:
        """Test if expired tokens are accepted."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        payload = decoded["payload"]
        
        # Check if token has expiration
        if "exp" not in payload:
            self.log("Token has no expiration claim", "info")
            return None
        
        current_time = int(time.time())
        token_exp = payload.get("exp", 0)
        
        # Check if token is already expired
        if token_exp < current_time:
            # Token is expired but we got baseline successfully
            # This means expired tokens are accepted!
            return self.create_finding(
                severity=Severity.HIGH,
                endpoint=path,
                method=method,
                title="Expired JWT Token Accepted",
                evidence=(
                    f"Server accepted expired JWT. "
                    f"Token expired at {token_exp} (timestamp), "
                    f"current time is {current_time}. "
                    f"Token has been expired for {(current_time - token_exp) // 3600} hours."
                ),
                verification=(
                    f"1. Check your JWT's 'exp' claim\n"
                    f"       2. Verify it's in the past\n"
                    f"       3. Confirm requests still succeed"
                ),
                confidence=90,
                cwe_id="CWE-613",
                references=[
                    "https://cwe.mitre.org/data/definitions/613.html",
                ],
            )
        
        # Create an expired token
        expired_payload = payload.copy()
        expired_payload["exp"] = current_time - 86400  # 24 hours ago
        
        # Re-sign with original signature (won't be valid but tests exp check)
        expired_token = self._create_token(
            decoded["header"],
            expired_payload,
            decoded["signature"]
        )
        
        response = await self.requester.send(
            endpoint,
            extra_headers={self.config.auth_header: f"Bearer {expired_token}"}
        )
        
        # This test is less reliable since signature won't match
        # Only report if server clearly doesn't validate expiration
        
        return None
    
    async def _test_weak_secrets(self, endpoint, decoded, baseline) -> Optional[Finding]:
        """Test for weak JWT secrets."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        header = decoded["header"]
        payload = decoded["payload"]
        
        # Only test HS256/HS384/HS512
        alg = header.get("alg", "")
        if not alg.startswith("HS"):
            return None
        
        for secret in self.WEAK_SECRETS:
            # Sign token with weak secret
            signature = self._sign_hs256(header, payload, secret)
            test_token = self._create_token(header, payload, signature)
            
            response = await self.requester.send(
                endpoint,
                extra_headers={self.config.auth_header: f"Bearer {test_token}"}
            )
            
            if response.is_success:
                similarity = self.analyzer.similarity(response, baseline)
                if similarity > 0.7:
                    return self.create_finding(
                        severity=Severity.CRITICAL,
                        endpoint=path,
                        method=method,
                        title="JWT Signed with Weak Secret",
                        evidence=(
                            f"Server accepted JWT signed with weak secret: '{secret}'. "
                            f"This allows attackers to forge arbitrary tokens."
                        ),
                        verification=(
                            f"1. Use jwt.io or similar to decode your token\n"
                            f"       2. Re-sign with secret '{secret}'\n"
                            f"       3. Verify the token is accepted"
                        ),
                        confidence=99,
                        cwe_id="CWE-521",
                        references=[
                            "https://cwe.mitre.org/data/definitions/521.html",
                        ],
                    )
        
        return None
    
    async def _test_empty_signature(self, endpoint, decoded, baseline) -> Optional[Finding]:
        """Test if empty signature is accepted."""
        path = endpoint.get("path", "")
        method = endpoint.get("method", "GET")
        
        # Create token with empty signature
        token = self._create_token(decoded["header"], decoded["payload"], "")
        
        response = await self.requester.send(
            endpoint,
            extra_headers={self.config.auth_header: f"Bearer {token}"}
        )
        
        if response.is_success:
            similarity = self.analyzer.similarity(response, baseline)
            if similarity > 0.5:
                return self.create_finding(
                    severity=Severity.CRITICAL,
                    endpoint=path,
                    method=method,
                    title="JWT Accepted with Empty Signature",
                    evidence=(
                        f"Server accepted JWT with empty signature. "
                        f"Response status: {response.status_code}."
                    ),
                    verification=(
                        f"1. Remove the signature portion of your JWT\n"
                        f"       2. Keep the two dots (header.payload.)\n"
                        f"       3. Verify access is granted"
                    ),
                    confidence=95,
                    cwe_id="CWE-347",
                )
        
        return None
