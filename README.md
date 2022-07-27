# okta-mfa-prompt-bombing

Utility script to send Okta Verify MFA prompts to users to simulate MFA prompt bombing

Users should not confirm prompts unless they were the ones logging in.



## Usage

Populate the `.env` file with an Okta API token and specify your Okta Org. 

The `OKTA_QUERY` variable sets the query filter to select the users to target. For testing purposes set a single email address. If empty, all users enrolled with Okta Verify push in the Okta org will be targeted. 

## Behavior  

Users are prompted in parallel, max. 10 at a time to avoid breaching API throttling limits on the Okta side.
The script will poll wether the user confirmed or rejected the MFA prompt. Prompts will timeout after 5 minutes if unanswerd (Okta defaults).

The script will print some basic statistics about the scenario in the end (how many users confirmed, rejected etc.) but I recommend to capture the runtime output so you can run your own analysis e.g. 

`go run prompt-bombing.go 2>&1| tee prompt_bombing.logs`

### What is the purpose of Multifactor Authentication (MFA)?
 
Even if your user account is protected with a strong password, a successful phishing attack or stolen credential can leave you vulnerable. MFA is a core defense preventing account takeovers. In general, accounts using MFA are more secure, since an attacker must compromise both the password and verification method to access your account. If an attacker has access to one, but not both, they will remain locked out.
Recent breaches show that MFA isn’t much of a hurdle for some hackers to clear.
 
### MFA prompt bombing
 
Once attackers gain access to a valid password they start issuing multiple MFA requests to the end user’s phone until the user accepts, resulting in unauthorized access to the account.
 
Methods include:
* Sending multiple MFA requests and hoping the user finally accepts one to make it stop (MFA fatigue).
* Calling the user, pretending to be part of the company, and telling them they need to send an MFA request as part of a company process.
* Paying employees for passwords and MFA approval



