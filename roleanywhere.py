from iam_rolesanywhere_session import IAMRolesAnywhereSession
from botocore.exceptions import NoCredentialsError
import argparse

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="IAM Roles Anywhere")
	parser.add_argument("--profileId", required=True, help="The profile id")
	parser.add_argument("--roleId", required=True, help="The role id")
	parser.add_argument("--trustId", required=True, help="The trust anchor id")
	parser.add_argument("--cert", required=True, help="The certificate file")
	parser.add_argument("--key", required=True, help="The private key file")
	parser.add_argument("--region", required=True, help="The region")
	parser.add_argument("--account", required=True, help="The account")
	parser.add_argument("--location", required=True,  choices=['cn', 'global'],help='The location parameter. Can be either "cn" or "global".')
	parser.add_argument("--file", required=True, help="The file to upload")
	parser.add_argument("--s3bucket", required=True, help="The s3 bucket")
	parser.add_argument("--s3folder", required=True, help="The s3 folder")
	args = parser.parse_args()
	aws_location = ""
	endpoint_input = ""
	if args.location == 'cn':
		aws_location = "aws-cn"
		endpoint_input = f"rolesanywhere.{args.region}.amazonaws.com.cn"
	elif args.location == 'global':
		aws_location = "aws"
		endpoint_input = f"rolesanywhere.{args.region}.amazonaws.com"
		
	
	trust = f"arn:{aws_location}:rolesanywhere:{args.region}:{args.account}:trust-anchor/{args.trustId}"
	profile = f"arn:{aws_location}:rolesanywhere:{args.region}:{args.account}:profile/{args.profileId}"
	role = f"arn:{aws_location}:iam::{args.account}:role/{args.roleId}"

	roles_anywhere_session = IAMRolesAnywhereSession(
		profile_arn=profile,
		role_arn=role,
		trust_anchor_arn=trust,
		certificate=args.cert,
		private_key=args.key,
		region=args.region,
		endpoint=endpoint_input
		).get_session()

	s3 = roles_anywhere_session.client("s3")
	files = args.file.split(',')

	for file in files:
		filename = file.split('/')[-1]
		s3_uri = f"{args.s3folder}/{filename}"
		try:
			s3.upload_file(file, args.s3bucket, s3_uri)
			print(f"File {file} uploaded to {s3_uri}")
		except FileNotFoundError:
			print(f"File {file} not found")
		except NoCredentialsError:
			print("Credentials not available")
