# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file
# except in compliance with the License. A copy of the License is located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS"
# BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under the License.

import json
import time
from urllib.request import urlopen
from jose import jwk, jwt
from jose.utils import base64url_decode

region = 'us-east-1'
userpool_id = 'us-east-1_HC0P4th3o'
app_client_id = '5gir3ibmnpkekfeq99f5viibrs'
keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region, userpool_id)
# instead of re-downloading the public keys every time
# we download them only on cold start
# https://aws.amazon.com/blogs/compute/container-reuse-in-lambda/
with urlopen(keys_url) as f:
  response = f.read()
keys = json.loads(response.decode('utf-8'))['keys']

def lambda_handler(event, context):
    token = event['token']
    # get the kid from the headers prior to verification
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']
    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break
    if key_index == -1:
        print('Public key not found in jwks.json')
        return False
    # construct the public key
    public_key = jwk.construct(keys[key_index])
    print(public_key)
    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit('.', 1)
    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        print('Signature verification failed')
        return False
    print('Signature successfully verified')
    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)
    # additionally we can verify the token expiration
    # if time.time() > claims['exp']:
    #     print('Token is expired')
    #     return False
    # # and the Audience  (use claims['client_id'] if verifying an access token)
    # if claims['aud'] != app_client_id:
    #     print('Token was not issued for this audience')
    #     return False
    # now we can use the claims
    print(claims)
    return claims
        
# the following is useful to make this script executable in both
# AWS Lambda and any other local environments
if __name__ == '__main__':
    # for testing locally you can enter the JWT ID Token here
    # event = {'token': 'eyJraWQiOiJCenFGbmNHSGVLVlVtU1wvQko2VVVGdXM5YjgxNCs4elhnWnJIXC85cU80aUU9IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI3OTVjNTZmZi1kZTg3LTQ1YzQtYjQwOS1kNDRlN2ZlM2E4MGQiLCJldmVudF9pZCI6ImY1NmQ3ZDA0LTNjYmYtNDU2My05NmFiLTFjNmQyZWRkODM5OSIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUiLCJhdXRoX3RpbWUiOjE2MTcyNDczNDEsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0hDMFA0dGgzbyIsImV4cCI6MTYxNzI1MDk0MSwiaWF0IjoxNjE3MjQ3MzQxLCJ2ZXJzaW9uIjoyLCJqdGkiOiJjOGYyZWQ4YS03YTliLTRhZDItOWEzZi1hYzBhNzQ3M2M1ZmEiLCJjbGllbnRfaWQiOiI1Z2lyM2libW5wa2VrZmVxOTlmNXZpaWJycyIsInVzZXJuYW1lIjoiNzk1YzU2ZmYtZGU4Ny00NWM0LWI0MDktZDQ0ZTdmZTNhODBkIn0.ALn1SYvZkjLI9MMoYDptdYz04kKa0XDvjvYjhUHEQoQRMeCy7FGRWGWqHb25UVo-zpglrrBxwVhH6r7ssxMBtviSyAt8rlqzcSkcDZ8hvCFQiR2uubulNl5CZtiA61owtljrAY-gEIBF0uRS5dvajdFWfllAAh0Bd9oETu0ENvBDQHpR-_xFEgARjRNXHWRtjs27C7xWRBAGFA1zYY7GSnHqxLSHu13QXJZax5RFEGfUJ-1Ou-Z5JmtP0PwpnayxE-yLv5kogT9HCDN_h8BfjMP3QelMaRlhqJELfLkYmqYve2o333jpPePxRat6_rlnE5zoaT2jBi2EZnZbGcs4qQ'}
    event = {'token': 'eyJraWQiOiJCenFGbmNHSGVLVlVtU1wvQko2VVVGdXM5YjgxNCs4elhnWnJIXC85cU80aUU9IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI3OTVjNTZmZi1kZTg3LTQ1YzQtYjQwOS1kNDRlN2ZlM2E4MGQiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6ImF3cy5jb2duaXRvLnNpZ25pbi51c2VyLmFkbWluIG9wZW5pZCBwcm9maWxlIGVtYWlsIiwiYXV0aF90aW1lIjoxNjE3MjUwMjE4LCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV9IQzBQNHRoM28iLCJleHAiOjE2MTcyNTM4MTgsImlhdCI6MTYxNzI1MDIxOCwidmVyc2lvbiI6MiwianRpIjoiNmRhNTEzZTctYjRjNi00ZWQwLWJiOTAtN2Y4MjI2ZjI3OWEzIiwiY2xpZW50X2lkIjoiNWdpcjNpYm1ucGtla2ZlcTk5ZjV2aWlicnMiLCJ1c2VybmFtZSI6Ijc5NWM1NmZmLWRlODctNDVjNC1iNDA5LWQ0NGU3ZmUzYTgwZCJ9.souwEI8DmUSUuMwziOxcD4Ve5xOxXq14Z4-eDzgXLhjENi1XkU59M_8o2By8AwC_2GPMqJrV1xBgx3WTIF3d3PuAHtyZfCBleRq7gs5khHaVqh9jQxFqmWE7LOkgfKXsRbstlOpbRFQqOCX0XvTusVm5MCssJdF3lvT7aGZf8iyT1vmqKg2vRJhoh-jRSNlVifFoCKHc6t84fbnsJTvr3CoCJxMtvICheCy2AngbZGy9QQUQFJEB1W76Ob07tBJZEVyqarn3i4-umWSWgbddWb8uGDlOA2ZFF3XO6SJ9JK_3z6LLfOds_IlEdiWXmMEkYo74zu1LYCgNV_EJLCYobw'}
    # event = {'token': 'eyJraWQiOiJJdHVrTkF3QXZvbHpuZlBlRlFaRWh1QlVnSmNMTnZtNzk3clVTVGgxaXZFPSIsImFsZyI6IlJTMjU2In0.eyJhdF9oYXNoIjoiOTZneTNuaVlsRlJfNEFtMlR4amVxdyIsInN1YiI6Ijc5NWM1NmZmLWRlODctNDVjNC1iNDA5LWQ0NGU3ZmUzYTgwZCIsImNvZ25pdG86Z3JvdXBzIjpbInVzLWVhc3QtMV9IQzBQNHRoM29fRmFjZWJvb2siXSwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0hDMFA0dGgzbyIsInBob25lX251bWJlcl92ZXJpZmllZCI6dHJ1ZSwiY29nbml0bzp1c2VybmFtZSI6Ijc5NWM1NmZmLWRlODctNDVjNC1iNDA5LWQ0NGU3ZmUzYTgwZCIsInByZWZlcnJlZF91c2VybmFtZSI6InZpbmNlbnQucGhhbTAxM0BnbWFpbC5jb20iLCJhdWQiOiI1Z2lyM2libW5wa2VrZmVxOTlmNXZpaWJycyIsImV2ZW50X2lkIjoiNjU4YTRiY2YtYTg3YS00NmJjLWEzMDEtMzhiMWY0ZjY1ZmIzIiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE2MTcyNjc1NTcsInBob25lX251bWJlciI6Iis4NDk2MzI1NTA5MyIsImV4cCI6MTYxNzI3MTE1NywiaWF0IjoxNjE3MjY3NTU4LCJlbWFpbCI6InZpbmNlbnQucGhhbTAxM0BnbWFpbC5jb20ifQ.R_tR8ohrhdDToZ5eRtLM4J3V-VpQabLszGKhIw1RUscMSgkXWI2R9oQA07--I1LyVNDvz3ox2bvb5ICKjMqxra224y0Drz9dZBGUk2YQerRfWJDu4SSj6huzabgFB_Vfjq1A5iv0V5b52gIBVELQFS6RLKv9m0wBwLbBYev1-F-KLoVBwElsg3jhvbn0rs93eMaPovqsPQPYn8xNTMr2EkreAylhp6ULshnaIuTfvZSyyqWtRN5fZX3sPPALrlCiayAE1alVXodKc2sgjjGe09CC875JC1u6MzEo68_J-HMCTkBwgdewE_r0cSQcGc2jqh7H_mKBIb6ORb9WWAV_Rg'}
    lambda_handler(event, None)
