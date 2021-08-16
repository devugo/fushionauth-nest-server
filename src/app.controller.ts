import { Controller, Get, Post, Req, Res } from '@nestjs/common';
import { AppService } from './app.service';
import { config } from './config';
import { generateChallenge, generateVerifier } from './helpers/pkce';
import * as APIRequest from 'request';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  getHello(): string {
    return this.appService.getHello();
  }

  @Get('/login')
  login(@Req() request: any, @Res() response: any): any {
    const session = request.session as any;

    // Generate and store the PKCE verifier
    session.verifier = generateVerifier();

    // Generate the PKCE challenge
    const challenge = generateChallenge(session.verifier);

    // Redirect the user to log in via FusionAuth
    response.redirect(
      `http://localhost:${config.fusionAuthPort}/oauth2/authorize?client_id=${config.clientID}&redirect_uri=${config.redirectURI}&response_type=code&code_challenge=${challenge}&code_challenge_method=S256`,
    );
  }

  @Get('/logout')
  logout(@Req() request: any, @Res() response: any): any {
    const session = request.session as any;

    // delete the session
    session.destroy();

    // end FusionAuth session
    response.redirect(
      `http://localhost:${config.fusionAuthPort}/oauth2/logout?client_id=${config.clientID}`,
    );
  }

  @Get('/oauth-callback')
  oauthCallback(@Req() request: any, @Res() response: any): any {
    const session = request.session as any;
    APIRequest(
      // POST request to /token endpoint
      {
        method: 'POST',
        uri: `http://localhost:${config.fusionAuthPort}/oauth2/token`,
        form: {
          client_id: config.clientID,
          client_secret: config.clientSecret,
          code: request.query.code,
          code_verifier: session.verifier,
          grant_type: 'authorization_code',
          redirect_uri: config.redirectURI,
        },
      },

      // callback
      (error, res, body) => {
        // save token to session
        session.token = JSON.parse(body).access_token;

        // redirect to the React app
        response.redirect(`http://localhost:${config.clientPort}`);
      },
    );
  }

  @Post('/set-user-data')
  setUserData(@Req() request: any): any {
    const session = request.session as any;

    // fetch the user using the token in the session so that we have their ID
    APIRequest(
      // POST request to /introspect endpoint
      {
        method: 'POST',
        uri: `http://localhost:${config.fusionAuthPort}/oauth2/introspect`,
        form: {
          client_id: config.clientID,
          token: session.token,
        },
      },

      // callback
      (error, res, body) => {
        const introspectResponse = JSON.parse(body);

        APIRequest(
          // PATCH request to /registration endpoint
          {
            method: 'PATCH',
            uri: `http://localhost:${config.fusionAuthPort}/api/user/registration/${introspectResponse.sub}/${config.applicationID}`,
            headers: {
              Authorization: config.apiKey,
            },
            json: true,
            body: {
              registration: {
                data: request.body,
              },
            },
          },
        );
      },
    );
  }

  @Get('/user')
  user(@Req() request: any, @Res() response: any): any {
    const session = request.session as any;
    if (session.token) {
      APIRequest(
        // POST request to /introspect endpoint
        {
          method: 'POST',
          uri: `http://localhost:${config.fusionAuthPort}/oauth2/introspect`,
          form: {
            client_id: config.clientID,
            token: session.token,
          },
        },

        // callback
        (error, res, body) => {
          const introspectResponse = JSON.parse(body);

          // valid token -> get more user data and send it back to the react app
          if (introspectResponse.active) {
            APIRequest(
              // GET request to /registration endpoint
              {
                method: 'GET',
                uri: `http://localhost:${config.fusionAuthPort}/api/user/registration/${introspectResponse.sub}/${config.applicationID}`,
                json: true,
                headers: {
                  Authorization: config.apiKey,
                },
              },

              // callback
              (error, res, body) => {
                response.send({
                  token: {
                    ...introspectResponse,
                  },
                  ...body,
                });
              },
            );
          }

          // expired token -> send nothing
          else {
            session.destroy();
            response.send({});
          }
        },
      );
    }

    // no token -> send nothing
    else {
      response.send({});
    }
  }
}
