import { handler } from './decode-verify-jwt';


async function main() {
  const result = await handler({
    // token: 'eyJraWQiOiJCenFGbmNHSGVLVlVtU1wvQko2VVVGdXM5YjgxNCs4elhnWnJIXC85cU80aUU9IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI3OTVjNTZmZi1kZTg3LTQ1YzQtYjQwOS1kNDRlN2ZlM2E4MGQiLCJldmVudF9pZCI6ImY1NmQ3ZDA0LTNjYmYtNDU2My05NmFiLTFjNmQyZWRkODM5OSIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUiLCJhdXRoX3RpbWUiOjE2MTcyNDczNDEsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0hDMFA0dGgzbyIsImV4cCI6MTYxNzI1MDk0MSwiaWF0IjoxNjE3MjQ3MzQxLCJ2ZXJzaW9uIjoyLCJqdGkiOiJjOGYyZWQ4YS03YTliLTRhZDItOWEzZi1hYzBhNzQ3M2M1ZmEiLCJjbGllbnRfaWQiOiI1Z2lyM2libW5wa2VrZmVxOTlmNXZpaWJycyIsInVzZXJuYW1lIjoiNzk1YzU2ZmYtZGU4Ny00NWM0LWI0MDktZDQ0ZTdmZTNhODBkIn0.ALn1SYvZkjLI9MMoYDptdYz04kKa0XDvjvYjhUHEQoQRMeCy7FGRWGWqHb25UVo-zpglrrBxwVhH6r7ssxMBtviSyAt8rlqzcSkcDZ8hvCFQiR2uubulNl5CZtiA61owtljrAY-gEIBF0uRS5dvajdFWfllAAh0Bd9oETu0ENvBDQHpR-_xFEgARjRNXHWRtjs27C7xWRBAGFA1zYY7GSnHqxLSHu13QXJZax5RFEGfUJ-1Ou-Z5JmtP0PwpnayxE-yLv5kogT9HCDN_h8BfjMP3QelMaRlhqJELfLkYmqYve2o333jpPePxRat6_rlnE5zoaT2jBi2EZnZbGcs4qQ',
    // token: 'eyJraWQiOiJCenFGbmNHSGVLVlVtU1wvQko2VVVGdXM5YjgxNCs4elhnWnJIXC85cU80aUU9IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI3OTVjNTZmZi1kZTg3LTQ1YzQtYjQwOS1kNDRlN2ZlM2E4MGQiLCJjb2duaXRvOmdyb3VwcyI6WyJ1cy1lYXN0LTFfSEMwUDR0aDNvX0ZhY2Vib29rIl0sImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0hDMFA0dGgzbyIsInZlcnNpb24iOjIsImNsaWVudF9pZCI6IjVnaXIzaWJtbnBrZWtmZXE5OWY1dmlpYnJzIiwiZXZlbnRfaWQiOiJkNzQ0YjkxZi1kNTg3LTQxMjItYThhMy04MTU1MGQyZTczNWEiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6ImF3cy5jb2duaXRvLnNpZ25pbi51c2VyLmFkbWluIG9wZW5pZCBwcm9maWxlIGVtYWlsIiwiYXV0aF90aW1lIjoxNjE3MzQ1OTMxLCJleHAiOjE2MTczNDk1MzEsImlhdCI6MTYxNzM0NTkzMiwianRpIjoiMTUzYzg3MTgtZGU2Ni00NDY0LTllYmQtMTg3ZjdkM2RiOWMxIiwidXNlcm5hbWUiOiI3OTVjNTZmZi1kZTg3LTQ1YzQtYjQwOS1kNDRlN2ZlM2E4MGQifQ.xEOAExRdub4aWRjMhx6H8OxZCd0S3DkAfPEIgtUTonBqeP1bumafy6g8s6gYdUeS89RO0Ej1TOLmfNGrbFjP7QehAl3p9lvizmK6AJjlYrZEQYSLXM_Wt1aJnrbgkUrcxBP3zAl8QghqRsKfH3uxujZMB69lTftRHgcvD8AzyVhjkLZjbmEy2YkLUNdWL9bK92cPQnaJ9h3k76V-yOWe6Tpe1_iK7c-SYYday-P6bD4u3E6Xp4ehcyiQ2zThJAeglHefvX_qsHty5FY6syzpwqNcvQ3dY590eEGgAxXJTY4Cpwb98ptcEWmXEkmdokZ5S_vgbeikE43kBAnTSQ84jw'
    // token: 'eyJraWQiOiJJdHVrTkF3QXZvbHpuZlBlRlFaRWh1QlVnSmNMTnZtNzk3clVTVGgxaXZFPSIsImFsZyI6IlJTMjU2In0.eyJhdF9oYXNoIjoiTVVoczZTSXB2YllIMFJHNmVWZThnZyIsInN1YiI6Ijc5NWM1NmZmLWRlODctNDVjNC1iNDA5LWQ0NGU3ZmUzYTgwZCIsImNvZ25pdG86Z3JvdXBzIjpbInVzLWVhc3QtMV9IQzBQNHRoM29fRmFjZWJvb2siXSwiZW1haWxfdmVyaWZpZWQiOnRydWUsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0hDMFA0dGgzbyIsInBob25lX251bWJlcl92ZXJpZmllZCI6dHJ1ZSwiY29nbml0bzp1c2VybmFtZSI6Ijc5NWM1NmZmLWRlODctNDVjNC1iNDA5LWQ0NGU3ZmUzYTgwZCIsInByZWZlcnJlZF91c2VybmFtZSI6InZpbmNlbnQucGhhbTAxM0BnbWFpbC5jb20iLCJhdWQiOiI1Z2lyM2libW5wa2VrZmVxOTlmNXZpaWJycyIsImV2ZW50X2lkIjoiZDc0NGI5MWYtZDU4Ny00MTIyLWE4YTMtODE1NTBkMmU3MzVhIiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE2MTczNDU5MzEsInBob25lX251bWJlciI6Iis4NDk2MzI1NTA5MyIsImV4cCI6MTYxNzM0OTUzMSwiaWF0IjoxNjE3MzQ1OTMyLCJlbWFpbCI6InZpbmNlbnQucGhhbTAxM0BnbWFpbC5jb20ifQ.ukIjFhZRNU9EKUop8jXttwJzRjPAKM-e7fTTm5Eok4CwpTGmkiDRw70bNUME60ZQPntBgtpI2_HSujXrHs8zGYwcDZhQ1knCJHD-N-eZKXFOx9OZlVSoxXe4XqTIM5X6Qwqt-V9NAyu8rA_W3xJk7MSzh4b4YlGRVXb9_atGaUtfh4w7DRqzSbQjeZ5x9QCKdv6hMei5dGrjgL1VYrRobiR9AWhx9kbxkoc-JXIqYNkke07Y33W71nft7zwOfO94f1o57gw23PApNboqMaQuy_C-JcqQJrfcoqml1P_HmvUmVlSlMMnfuqL-BRaCNxnWHV-Q_rXwUI7PpflvEenZgw'
    token: 'eyJraWQiOiJCenFGbmNHSGVLVlVtU1wvQko2VVVGdXM5YjgxNCs4elhnWnJIXC85cU80aUU9IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI3OTVjNTZmZi1kZTg3LTQ1YzQtYjQwOS1kNDRlN2ZlM2E4MGQiLCJjb2duaXRvOmdyb3VwcyI6WyJ1cy1lYXN0LTFfSEMwUDR0aDNvX0ZhY2Vib29rIl0sImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xX0hDMFA0dGgzbyIsInZlcnNpb24iOjIsImNsaWVudF9pZCI6IjVnaXIzaWJtbnBrZWtmZXE5OWY1dmlpYnJzIiwiZXZlbnRfaWQiOiJkMjM2YmE2OC01ZDdiLTRhNTgtYjc2MC03ZTQ0ZTA0NjE4MTkiLCJ0b2tlbl91c2UiOiJhY2Nlc3MiLCJzY29wZSI6ImF3cy5jb2duaXRvLnNpZ25pbi51c2VyLmFkbWluIG9wZW5pZCBwcm9maWxlIGVtYWlsIiwiYXV0aF90aW1lIjoxNjE3MzUwMzI4LCJleHAiOjE2MTczNTM5MjgsImlhdCI6MTYxNzM1MDMyOCwianRpIjoiMGRlY2U0YzAtZWM1Ny00ZGFlLTg0NTMtYjI1ODhlYTEwOTU4IiwidXNlcm5hbWUiOiI3OTVjNTZmZi1kZTg3LTQ1YzQtYjQwOS1kNDRlN2ZlM2E4MGQifQ.ICSWDdwVkEHjKemuMjc3weLjYPaQr99kz9fR0gCU9Ytva0UgMWDs6tAglugGGBdpCY668Vca9lrDASSRY5aRaNpCc8arv-J4T1gLVnVHACjGfOM-UPiJdIWo67FTLL4YGd2xDSuJYCLkSJqtmTeRr3Ydwjo3-akK_b6imDZuX3ar1RoeAdwlSij2_Ce15ANLPAGLl5fvfbBdI_ggEjl3bZwITuBnFCssCba4PfSdpaO_N0P_7Bp-JOu6XKrMHRQiyfrKVKr4H_1b7GLw9Iaw0lZLUpg4q6whgXANlS0v59Fk4QBCNJ5YkX8eFYNrihW9jfSjc_K0RqNT6VdZPxUYBg'
  });

  console.log(`Decoded jwt token: ${result}`);
}

main();