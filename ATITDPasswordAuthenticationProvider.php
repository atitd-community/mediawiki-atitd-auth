<?php namespace ATITDAuth;

require __DIR__ . '/vendor/autoload.php';

use User;
use Status;
use Exception;
use StatusValue;
use MWCryptRand;
use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;
use DBAccessObjectUtils;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\PasswordAuthenticationRequest;

class ATITDPasswordAuthenticationProvider
	extends \MediaWiki\Auth\AbstractPasswordPrimaryAuthenticationProvider
{

	// This is the official endpoint for authenticating against the
	// ATITD user account and is configured in LocalSettings.php
	protected $apiUrl = false;

	/**
	 * Sets up the extension and sets the API URL.
	 *
	 * @param array $params
	 */
	public function __construct( $params = [] ) {
		parent::__construct( $params );
		$this->apiUrl = $params['apiUrl'];
	}

	/**
	 * A typical MediaWiki authentication flow attempts to authenticate
	 * the userlocally and if that fails call the remote login code.
	 *
	 * @param array $reqs
	 *
	 * @return \MediaWiki\Auth\AuthenticationResponse
	 */
	public function beginPrimaryAuthentication( array $reqs ) {

		$req = AuthenticationRequest::getRequestByClass( $reqs, PasswordAuthenticationRequest::class );
		if ( !$req ) {
			return AuthenticationResponse::newAbstain();
		}

		if ( $req->username === null || $req->password === null ) {
			return AuthenticationResponse::newAbstain();
		}

		$username = User::getCanonicalName( $req->username, 'usable' );
		if ( $username === false ) {
			return AuthenticationResponse::newAbstain();
		}

		$status = $this->checkPasswordValidity( $username, $req->password );
		if ( !$status->isOK() ) {
			return AuthenticationResponse::newFail( $status->getMessage() );
		}

		$fields = [
			'user_id', 'user_password', 'user_password_expires',
		];

		$dbr = wfGetDB( DB_REPLICA );
		$row = $dbr->selectRow(
			'user',
			$fields,
			[ 'user_name' => $username ],
			__METHOD__
		);

		if ( $row ) {
			$pwhash = $this->getPassword( $row->user_password );
			if ( !$pwhash->equals( $req->password ) ) {
				// User exists locally but password doesn't match or is blank
				if($this->desertNomadLogin( $username, $req->password )) {
					$this->updateUserWithDesertNomadCredentials($row->user_id, $username, $req->password);
				}
			}
		} else {
			// User doesn't exist locally
			if($this->desertNomadLogin( $username, $req->password )) {
				$this->createUserWithDesertNomadCredentials($username, $req->password);
			}
		}

		# We abstain here to let the primary password authentication provider
		# handle all the login stuff, since the user has been set up correctly
		return AuthenticationResponse::newAbstain();
	}

	/**
	 * Sends a remote request to the authentication server
	 * verifying the username and password combination.
	 *
	 * @param string $username
	 * @param string $password
	 *
	 * @return bool
	 */
	protected function desertNomadLogin( $username, $password ) {

		$client = new Client(['cookies' => true]);

		$response = $client->request('POST', $this->apiUrl, [
			RequestOptions::JSON =>
				['username' => $username,
				 'password' => $password]
		]);

		$test = $response->getBody()->getContents();

		$result = $this->checkDesertNomadLoginResponse($test);

		if($result === true) {
			wfDebugLog( 'ATITDAuth', "SuccessLogin for {$username}" );
			$this->username = $username;
			return true;
		}

		wfDebugLog( 'ATITDAuth', "FailLogin for {$username}" );

		return false;
	}

	/**
	 * Converts the response we receive from the game's
	 * server from JSON and returns it as a boolean.
	 *
	 * @param string $responseContent
	 *
	 * @return bool
	 */
	protected function checkDesertNomadLoginResponse($responseContent) {

		$decoded = json_decode($responseContent);

		return $decoded->Result;
	}

	/**
	 * The user exists locally, but the password did not match or was blank, however,
	 * authentication was successful against the game's auth server. This means we
	 * should update the local user with these credentials since they're valid.
	 *
	 * @param int $id
	 * @param string $username
	 * @param string $password
	 *
	 * @return bool
	 */
	protected function updateUserWithDesertNomadCredentials($id, $username, $password) {

		$newHash = $this->getPasswordFactory()->newFromPlaintext( $password );

		$dbw = wfGetDB( DB_MASTER );
		$dbw->update(
			'user',
			[ 'user_password' => $newHash->toString() ],
			[ 'user_id' => $id ],
			__METHOD__
		);

		$user = User::newFromId( $id );
		$user->setToken();

		$user->saveSettings();

		return true;
	}

	/**
	 * The user doesn't exist locally however authentication was successful
	 * against the games auth server. So this means we should create the
	 * local user with these credentials since we know they're valid.
	 *
	 * @param int $id
	 * @param string $username
	 * @param string $password
	 *
	 * @return bool
	 */
	protected function createUserWithDesertNomadCredentials($username, $password) {

		$user = User::newFromName( $username );
		if ( !is_object( $user ) ) {
			$this->fatalError( "invalid username." );
		}

		$exists = ( 0 !== $user->idForName() );

		if ( !$exists ) {
			# Insert the account into the database
			$user->addToDatabase();
			$user->saveSettings();
		}

		return $this->updateUserWithDesertNomadCredentials($user->getId(), $username, $password);
	}

	# We'll worry about the specifics ourselves
	public function testUserCanAuthenticate( $username ) {
		return true;
	}

	# We'll worry about the specifics ourselves
	public function testUserExists( $username, $flags = User::READ_NORMAL ) {
		return true;
	}

	public function providerAllowsAuthenticationDataChange(
		AuthenticationRequest $req, $checkData = true
	) {
		return StatusValue::newGood( 'ignored' );
	}

	public function providerChangeAuthenticationData( AuthenticationRequest $req ) {
		return;
	}

	public function accountCreationType() {
		return self::TYPE_CREATE;
	}

	public function testForAccountCreation( $user, $creator, array $reqs ) {
		return StatusValue::newGood();
	}

	public function beginPrimaryAccountCreation( $user, $creator, array $reqs ) {
		return AuthenticationResponse::newAbstain();
	}

	public function finishAccountCreation( $user, $creator, AuthenticationResponse $res ) {
		return null;
	}
}



