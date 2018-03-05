__author__ = 'Dariq'

import httplib2
import argparse
import sys
import logging
import json

from apiclient import discovery
from oauth2client import client
from oauth2client import tools
from oauth2client.file import Storage

APPLICATION_NAME='GmailHandler'
OAUTH_SCOPE = 'https://mail.google.com.modify'

def main():
    ## Get the command line arguments for the gmail tools
    tool_flags = argparse.ArgumentParser(parents=[tools.argparser]).parse_args()

    ##Set the logging level
    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)
    logging.getLogger('googleapicliet.discovery_cache').setLevel(logging.ERROR)

    ##load the handler config
    logging.info("Retrieving handler configuration from handler_config.json")
    with open("handler_config.json") as handler_config_file:
        handler_config = json.loads(handler_config_file.read())

    ##Get the credentials
    logging.info("Retrieving the credentials")
    credentials = getCredentials(handler_config["secret_file_location"], handler_config["storage_location"], tool_flags)

    perform_actions(handler_config, credentials)

def perform_actions(handler_config, credentials):
    for action_item in handler_config["actions"]:
        doAction({"name": action_item["action"], "action": action_item["value"]}, credentials)

def addCommandLineArguments( parser ):
    parser.add_argument('-s', '--secret-file', dest='secret_file', help="Location of the secret file", required=True)
    parser.add_argument('-g', '--storage', dest='storage', help="Location of the credential storage file", required=True)

    parser.add_argument('--delete-subject', dest='subject_to_delete',
                        action='store', help="Delete messages based on subject")

    parser.add_argument('--delete-start-date', dest='date_to_delete_from',
                        action='store', help="Deletion start date")

    parser.add_argument('--delete-end-date', dest='delete_end_date',
                        action='store', help="Deletion end date")

    parser.add_argument('--delete-from', dest='delete_from',
                        action='store', help="Delete messages sent from a certain email address")



    return parser

def getCredentials(secret_file_location, storage_file_location, tool_flags):
    ##Path to the client_secret.json file downloaded from the Developer Console
    CLIENT_SECRET_FILE = secret_file_location

    # Check https://developers.google.com/gmail/api/auth/scopes
    # for all available scopes
    # TODO enhance so that the modify privilege isn't for everyone if need be
    OAUTH_SCOPE = 'https://mail.google.com/'

    #Location of the credentials storage file
    STORAGE = Storage(storage_file_location)

    ##Start the OAuth flow to retrieve credentials
    flow = client.flow_from_clientsecrets(CLIENT_SECRET_FILE, OAUTH_SCOPE)
    flow.user_agent = APPLICATION_NAME
    http = httplib2.Http()

    ##Try to retrieve credentials from storage or run the flow to generate them
    credentials = STORAGE.get()
    if credentials is None or credentials.invalid:
        credentials = tools.run_flow(flow, STORAGE, tool_flags)

    return credentials

def getGmailService( credentials):
    # Authorize the httplib2.Http object with our credentials
    http = httplib2.Http()
    http = credentials.authorize(http)

    # Build the Gmail service from discovery
    return discovery.build('gmail', 'v1', developerKey='AIzaSyCh3pWmGDoB2s2PshQb99GctUgB1Cp_hUw', http=http)

def doAction(actions, credentials ):

    if actions["name"] == "delete-subject":
        deleteBasedOnSubject(actions["action"], credentials)

    elif actions["name"] == "delete-from":
        print("Deleting emails with from email address: %s" % (actions["action"]))
        deleteBasedOnEmailAddress(actions["action"], credentials)


def deleteBasedOnSubject(subject, credentials):
    # Retrieve a page of threads
    subject_to_query = buildSubject(subject)
    messages = getAllMessages(credentials, subject_to_query)

    ##Check to see if there is anything to delete
    if len(messages) == 0:
        print("There are no messages to delete with subject: %s" % (subject_to_query))
        return

    print("Successfully retrieved messages from gmail for deletion")
    print("Preparing to delete the messages with subject: %s" % (subject_to_query))

    for message in messages['messages']:
        deleteMessage(message['id'])

    print("Successfully deleted %d messages with subject: %s" % (len(messages),subject_to_query))

def buildSubject( subject ):
    return "subject:" + subject

def deleteBasedOnEmailAddress( email_address, credentials ):
    query_for_email_address = buildEmailAddress(email_address)
    messages = getAllMessages(credentials, query_for_email_address)
    print(messages)

    ##Check to see if there is anything to delete
    if len(messages) == 0:
        print("There are no messages to delete with email address: %s" % (email_address))
        return

    print("Successfully retrieved messages from gmail for deletion")
    print("Preparing to delete the messages with the email address: %s" % (email_address))

    for message in messages:
        deleteMessage(credentials, message['id'])

    print("Successfully deleted %d messages with email address: %s" % (len(messages), email_address))

def buildEmailAddress( email_address ):
    return "from:" + email_address

def getAllMessages( credentials, query ):
    messages_to_return = []

    response = getGmailService(credentials).users().messages().list(userId='me', q=query).execute()

    if 'messages' in response:
        messages_to_return.extend(response['messages'])

    while 'nextPageToken' in response:
        page_token = response['nextPageToken']

        response = getGmailService(credentials).users().messages()\
            .list(userId='me', q=query, pageToken=page_token).execute()

        messages_to_return.extend(response['messages'])

    return messages_to_return

def getMessage( credentials, message_id ):
    return getGmailService(credentials).users().messages().get(userId='me', id=message_id).execute()

def deleteMessage( credentials, message_id ):
    getGmailService(credentials).users().messages().delete(userId='me', id=message_id).execute()


if __name__ == "__main__":
    main()