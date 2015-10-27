<?php
/*
 * Copyright 2012 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Credentials object used for OAuth 2.0 Signed JWT assertion grants.
 *
 * @author Chirag Shah <chirags@google.com>
 */
class Google_AssertionCredentials {
  const MAX_TOKEN_LIFETIME_SECS = 3600;

  public $serviceAccountName;
  public $scopes;
  public $privateKey;
  public $privateKeyPassword;
  public $assertionType;
  public $sub;
  /**
   * @deprecated
   * @link http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06
   */
  public $prn;

  /**
   * @param $serviceAccountName
   * @param $scopes array List of scopes
   * @param $privateKey
   * @param string $privateKeyPassword
   * @param string $assertionType
   * @param bool|string $sub The email address of the user for which the
   *               application is requesting delegated access.
   */
  public function __construct(
      $serviceAccountName,
      $scopes,
      $privateKey,
      $privateKeyPassword = 'notasecret',
      $assertionType = 'http://oauth.net/grant_type/jwt/1.0/bearer',
      $sub = false) {
    $this->serviceAccountName = $serviceAccountName;
    $this->scopes = is_string($scopes) ? $scopes : implode(' ', $scopes);
    $this->privateKey = $privateKey;
    $this->privateKeyPassword = $privateKeyPassword;
    $this->assertionType = $assertionType;
    $this->sub = $sub;
    $this->prn = $sub;
  }

  public function generateAssertion() {
    $now = time();
    $signedJWT = new \Xtuple\Common\JWT\SignedJWT\RS256SignedJWT(
      new \Xtuple\Common\JWT\JWT(
        new \Xtuple\Common\JWT\RegisteredClaims(
          $this->serviceAccountName,
          $this->sub,
          Google_OAuth2::OAUTH2_TOKEN_URI,
          $now,
          $now + self::MAX_TOKEN_LIFETIME_SECS,
          "",
          ""
        ), [], [
          "scope" => $this->scopes,
          "prn" => $this->sub,
        ]
      ), new \Xtuple\Common\SSL\PKCS12\PKCS12File(
        new \Xtuple\Common\File\File($this->privateKey),
        $this->privateKeyPassword
      )
    );
    return $signedJWT->encode();
  }
}
