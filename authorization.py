import json
import re
from datetime import datetime, timedelta

USER_POLICY = [
    {
        "Sid": "UserPolicy1",
        "Effect": "Deny",
        "Action": "footprint:getlist|footprint:getitem",
        "Resource": "kamId:94",
    }
]

ROLE_POLICY = [
    {
        "Sid": "RolePolicy1",
        "Effect": "Allow",
        "Action": "footprint:getlist|footprint:getitem",
        "Resource": "countryid:08.*|globalAccountId:900",
    },
    {
        "Sid": "RolePolicy2",
        "Effect": "Deny",
        "Action": "footprint:getlist|footprint:getitem",
        "Resource": "(?=.*countryid:070)(?=.*globalaccountid:901)",
    }
]


def get_object() -> dict:
    """Get object"""
    with open('object.json', 'r', encoding='utf-8') as fp:
        return json.load(fp)


def get_statement_regex_object(statement: dict) -> dict:
    """Get regex object"""
    result = {}
    result['Sid'] = statement['Sid']
    result['Effect'] = statement['Effect']
    result['Resource'] = re.compile(statement.get('Resource', '').lower(), flags=re.IGNORECASE)
    result['Action'] = re.compile(statement['Action'].lower(), flags=re.IGNORECASE)
    return result


def get_authorization_object(obj: dict) -> str:
    """Get auth object"""
    result = json.dumps(obj).replace('"', '').replace(': ', ':').lower()
    return result


def authorize(action: str, obj: dict, policy: list) -> tuple:
    """Authorize"""
    authorized = False

    # Prepare/compile statements
    deny_statements = [get_statement_regex_object(x) for x in policy if x['Effect'] == 'Deny']
    allow_statements = [get_statement_regex_object(x) for x in policy if x['Effect'] == 'Allow']

    # Prepare authorization object
    auth_object = get_authorization_object(obj)

    # Test if there is a statement for the resource
    denied_by_resource = [x for x in deny_statements if x['Resource'].search(auth_object)]
    allowed_by_resource = [x for x in allow_statements if x['Resource'].search(auth_object)]

    # Test if there is a statement for the action
    denied_by_action = [x for x in denied_by_resource if x['Action'].search(action)]
    if denied_by_action:
        return False, denied_by_action

    allowed_by_action = [x for x in allowed_by_resource if x['Action'].search(action)]
    if allowed_by_action:
        authorized = True, allowed_by_action

    return authorized, None


def main():
    """Main function"""
    footprint = get_object()
    action = 'footprint:getlist'

    iterations = 10
    start = datetime.now()
    policy = [*USER_POLICY, *ROLE_POLICY]

    authorized = False, None
    for i in range(iterations):
        authorized = authorize(action, footprint, policy)

    end = datetime.now()
    elapsed = (end - start) / timedelta(milliseconds=1)

    print(authorized)
    print(f'{elapsed:.3f} ms, {elapsed / iterations:.3f} ms per iteration')


if __name__ == '__main__':
    main()
