import asyncio
import time


def close():
    """
    Function used to close the connection between the client and the server.
    """

    print('[!] Closing connection')
    time.sleep(1)
    print('[!] Exiting')
    time.sleep(1)
    print("-------------    Connection  Closed    -------------\n")


def commands():
    """
    Function used to print all the commands available.
    """

    print("[*] Commands:\n\n")
    print("[ register ]\n\t< Register a new user to the server using the <username> ")
    print("\tand <password> provided. If a user is already registered with the")
    print("\tprovided <username>, the request is to be denied with a proper message highlighting ")
    print("\tthe error for the user. A new personal folder ")
    print("\tnamed <username> should be created on the server. >")
    print("\n[ login ]\n\t< Log in the user conforming with <username> onto the server if the ")
    print("\t<password> provided matches the password used while registering.")
    print("\tIf the <password> does not match or if the <username> does not exist, an error ")
    print("\tmessage should be returned to the request for the client to present")
    print("\tto the user. >")
    print("\n[ create_folder ]\n\t< Create a new folder with the specified <name> in the current ")
    print("\tworking directory for the user issuing the request. If a")
    print("\tfolder with the given name already exists, the request is to be denied with a ")
    print("\tproper message highlighting the error for the user.  >")
    print("\n[ write_file ]\n\t< Write the data in <input> to the end of the file <name> in ")
    print("\tthe current working directory for the user issuing the request,")
    print("\tstarting on a new line.  If no file exists with the given <name>, a new file is to ")
    print("\tbe created in the current working directory for the user. >")
    print("\n[ read_file ]\n\t< Read data from the file <name> in the current working directory ")
    print("\tfor the user issuing the request and return the first")
    print("\thundred characters in it. Each subsequent call by the same client is to return the ")
    print("\tnext hundred characters in the file, up until all characters")
    print("\tare read. If a file with the specified <name> does not exist in the current ")
    print("\tworking directory for the user, the request is to be denied with a")
    print("\tproper message highlighting the error for the user.  >")
    print("\n[ change_folder ]\n\t< Move the current working directory for the current user to ")
    print("\tthe specified folder residing in the current folder.")
    print("\tIf the <name> does not point to a folder in the current working directory, the ")
    print("\trequest is to be denied with a proper message highlighting")
    print("\tthe error for the user. >")
    print("\n[ list ]\n\t< Print all files and folders in the current working directory for the ")
    print("\tuser issuing the request. This command is expected to give")
    print("\tinformation about the name, size, date and time of creation, in an easy-to-read ")
    print("\tmanner. Shall not print information regarding content in ")
    print("\tsub-directories. >")
    print("\n[ id ]\n\t< Show the current user >")


async def tcp_echo_client():
    """
    Main Client function to establish the connection with the Server
    """

    print('\n[SYSTEM] Client side: type < commands > to show all available commands.\n')
    reader, writer = await asyncio.open_connection('127.0.0.1', 8088)

    # Loop for sending and receiving messages
    while True:
        message = input('[$] > ')

        # Message to the server
        writer.write(message.encode())
        if message == "commands":
            commands()
            continue
        elif message == 'exit':
            break

        # Message from the server
        data = await reader.read(2048)
        print(f'{data.decode()}')

    # Closes the connection.
    close()
    time.sleep(1)
    writer.close()

asyncio.run(tcp_echo_client())
