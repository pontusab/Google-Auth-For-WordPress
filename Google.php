<?php

namespace Auth;

class Google extends \Exception
{
	public static $clientId;
	public static $clientSecret;
	public static $domain;
	public static $scope;
	public static $role;
	protected $redirectUri;
	protected $code;
	protected $token;


	
    /**
     * Add information from: https://code.google.com/apis/console/
     *
     * @param Google::$clientId The Client ID.
     * @param Google::$clientSecret The Client secret.
     * @param $redirectUri The Redirect Url.
     * @param $code The callback code.
     */

	public function __construct()
	{
		if( !Google::$clientId || !Google::$clientSecret || !Google::$domain )
		{
			throw new Exception( 'Invalid credentials.' );
		}
		else
		{
			$this->redirectUri   = get_bloginfo( 'url' );
			$this->code   		 = isset( $_GET['code'] ) ? $_GET['code'] : null;
			$this->handleLogout();
			$this->handle();
		}
	} 


	public function handleLogout()
	{
		$logout = isset( $_GET['action'] ) ? $_GET['action'] : false;

		if( $logout && $logout === 'logout' )
		{
			wp_clear_auth_cookie();

			wp_redirect( site_url( 'login' ) ); 

		    exit;
		}
	}


	/**
     * Handles incoming authentication requests.
     *
     * @param Request $request The request object.
     */

	public function handle()
	{
		try 
	    {
			// Chek for the code callback, the nonce and not logged in
			if( $this->code && wp_verify_nonce( $_GET['state'], 'state' ) && !is_user_logged_in() )
			{
				$response = wp_remote_request( 'https://accounts.google.com/o/oauth2/token', array(
			        'method'    => 'POST',
			        'timeout'   => 60,
			        'sslverify' => true,
			        'body' =>  array(
			           	'code' 	   		=> $this->code,
			            'client_id' 	=> Google::$clientId,
			            'client_secret' => Google::$clientSecret,
			            'redirect_uri' 	=> $this->redirectUri,
			            'grant_type'    => 'authorization_code'
			        )
			    ));

			    $this->token = json_decode( $response['body'] )->access_token;

			    if( !empty( $this->token ) )
			    {
			    	$user = $this->userInfo( $this->token );

			    	$this->findUser( $user );
			    }
			    else
			    {
			    	throw new Exception( 'Invalid token.' );
			    }
			}
		}

		catch( Exception $e ) 
		{
		    echo 'Caught exception: ',  $e->getMessage();
		}
	}


	/**
     * Gets the user info from Google
     * 
     * @param Token $token generated from handle() function
     * @return Object user data
     */

	public function userInfo( $token )
	{
		$response = wp_remote_request( 'https://www.googleapis.com/oauth2/v1/userinfo?access_token=' . $token );
	
		$data = json_decode( $response['body'] );

		return (object) array(
			'ID' 	 	 	 => $data->id,
			'email' 		 => $data->email,
			'verified_email' => $data->verified_email,
			'name' 			 => $data->name,
			'given_name' 	 => $data->given_name,
			'family_name' 	 => $data->family_name,
			'hd' 			 => $data->hd,
		);
	}


	/**
     * Generate login/logout links
     * 
     * @param $loginText and logoutText 
     * @return html link
     */

	public function loginOut( $loginText = false, $logoutText = false, $class = false )
	{
		if( !is_user_logged_in() )
		{
			$url = sprintf( 
		        'https://accounts.google.com/o/oauth2/auth?client_id=%s&response_type=%s&scope=%s&redirect_uri=%s&state=%s',
				Google::$clientId,
				urlencode( 'code' ),
				urlencode( Google::$scope ),
				urlencode( $this->redirectUri ),
				wp_create_nonce( 'state' )
		    );

		    $link = '<a href="'. $url .'" class="'. $class .'">'.( !empty( $loginText ) ? $loginText : __( 'Login with Google Account' ) ).'</a>';
		}
		else
		{
			$link = '<a href="'. wp_logout_url() .'" class="'. $class .'">'.( !empty( $logoutText ) ? $logoutText : __( 'Logout' ) ).'</a>';
		}

		return $link;
	}

	/**
     * Try to find a specific user based on the Google response
     * Else add a new user to WordPress
     * 
     * @param $user data from the API response
     */

	public function findUser( $user )
    {
    	try 
	    {
	    	if( strstr( $user->email, Google::$domain ) !== FALSE )
	    	{
		        $userID = current( get_users( array(
		            'meta_key' 	 => 'uid',
		            'meta_value' => $user->ID,
		            'fields' 	 => 'ID'
		        )));


		        if( !$userID )
		        {
		        	$userData = array(
						'ID' 			=> '',
						'user_login'	=> $user->email,
						'user_email'	=> $user->email,
						'user_nicename' => $user->name,
						'display_name'	=> $user->name,
						'role'			=> Google::$role,
						'user_pass'     => wp_generate_password(),
					);

		        	$userID = wp_insert_user( $userData );

		        	if( $userID > 0 )
		        	{
		        		update_user_meta( $userID, 'uid', $user->ID );
		        	}
		        	else
		        	{
		        		throw new Exception( 'Could not add uid to user.' );
		        	}
		        }

		        wp_set_auth_cookie( $userID, true );
		        wp_redirect( home_url() ); 

		        exit;
		    }
		    else
		    {
		    	throw new Exception( 'Only ' . Google::$domain . ' are allowed to login!' );
		    }
		}
	  
		catch( Exception $e ) 
		{
		    echo 'Caught exception: ',  $e->getMessage();
		}
	}
}
