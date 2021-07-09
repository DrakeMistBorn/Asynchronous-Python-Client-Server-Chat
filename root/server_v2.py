import asyncio
import os
import signal
import time

signal.signal(signal.SIGINT, signal.SIG_DFL)
o_path = os.getcwd()


def register(username, password):
    """
    Function used to register the new user into the server.
    :return: None.
    """

    pass_file = open('pass.txt', 'a')
    pass_file.write(f'\n{username},{password}')
    pass_file.close()
    logged = True
    create_folder(o_path, logged, username)


def login(o_path, username, password):
    """
    Function used to login in the user to the server.
    :return: Returns User's path, if the user is logged and
    an alert message if the username is wrong.
    """

    alert_msg = ''
    logged = False
    original_path = ''

    if os.getcwd().endswith('\\root'):
        pass_file = open('pass.txt', 'r')
    else:
        pass_file = open(o_path + '\\' + 'pass.txt', 'r')

    # This loop reads each line in the file with the users and passwords
    for line in pass_file.readlines():
        us = line.split(',')

        # Checks if the username and password introduced are equal to the ones
        # written in the pass.txt.
        if us[0].strip() == username and us[1].strip() == password:
            logged = True
            original_path = os.getcwd()
            # change_folder(username, logged)
            pass_file.close()
    if not logged:
        alert_msg = 'User does not exist.'
        pass_file.close()

    pass_file.close()
    return original_path, logged, alert_msg


def create_folder(o_path, logged, folder_name):
    """
    This function creates a folder inside the current user path.
    :return: Returns and exception if the folder already exist.
    """

    if logged:
        try:

            # Creates a folder in the current directory.
            os.mkdir(o_path + "\\" + folder_name)
            return True
        except Exception as inst:
            send_error = [False, type(inst), inst.args, inst]
            return False, send_error
    else:
        return False


def write_file(o_path, file_name, logged, message):
    """
    Writes inside the file given the message that the user wants. If it doesn't exist,
    the file is created.
    :return: Returns True or False if the file was writen or not.
    """

    # This if conditional prevents from path traversal.
    if logged:
        open_file = open(o_path + '\\' + file_name, 'a')
        open_file.write(f'{message}\n\t')
        open_file.close()
        return True
    else:
        return False


def change_folder(o_path, new_folder, logged):
    """
    Changes the folder directory.
    :return: Returns true or false if the change was possible.
    """
    # if save_path(o_path, new_folder, username):
    if logged:
        try:

            # Changes the current directory.
            os.chdir(o_path + "\\" + new_folder)
            return True
        except:
            return False
    else:
        return False
    # else:
    # return False


def safe_path(o_path, path, new_folder, username):
    path = path + new_folder + '\\'
    save = False
    for users in os.listdir(o_path):
        if users == username:
            continue
        else:
            if path.__contains__(users) or path.__contains__("root"):
                save = False
                return save
            else:
                if not safe_comps(path):
                    save = False
                    return save
                else:
                    save = True
    return save


def safe_comps(path):
    sep = '\\'
    dots = 1
    words = 0
    comps = path.split(sep)
    for i in comps:
        if i == "..":
            dots += 1
        else:
            words += 1
    if dots >= words:
        return False
    else:
        return True


def listt(logged, username, o_path, path):
    """
    Lists the folders and files inside the current directory.
    :return: Returns a list with all the files / folders.
    """

    list_to_send = "FILE\t->\tDATE\t->\tSIZE"
    if logged:
        if not os.getcwd().__contains__(username):
            # This loop reads each file / folder and it puts in a string variable its data.
            for lines in os.listdir(o_path + "\\" + path):
                text = "- " + lines + "\t->\t" + time.ctime(os.path.getmtime(o_path + "\\" + path)).__str__() + \
                       "\t->\t" + os.path.getsize(o_path + "\\" + path + "\\" + lines).__str__()
                list_to_send = list_to_send + "\n" + text

            return list_to_send
        else:
            for lines2 in os.listdir(o_path + "\\" + path):
                text = "- " + lines2 + "\t->\t" + time.ctime(os.path.getmtime(o_path + "\\" + path)).__str__() + \
                       "\t->\t" + os.path.getsize(o_path + "\\" + path + "\\" + lines2).__str__()
                list_to_send = list_to_send + "\n" + text
                return list_to_send
    else:
        return False


async def handle_echo(reader, writer):
    """
    Main function of the server. It manages the commands accepted by the server.
    """

    path = '\\'
    username = None
    logged = False
    openedfile = False
    addr = writer.get_extra_info('peername')
    print(f"[!] {addr} is connected to the server")

    while True:
        data = await reader.read(2048)
        message = data.decode().strip()

        if message == 'exit':
            # If a client wants to disconnect, prints in the server which user was disconnected.
            print(f'[!] {addr} is disconnected\n')
            break

        if message == 'read_file' and logged:
            textosend = ''
            writer.write('[*] File name: '.encode())
            await writer.drain()
            file_read = await reader.read(2048)
            file_read = file_read.decode().strip()
            if safe_path(o_path, path, file_read, username):
                path_read_file = path + file_read
                if os.path.normpath(os.getcwd() + '\\' + username + '\\' + path_read_file).startswith(o_path + "\\" + username):

                    # If the file is not open, opens the file to read it.
                    if not openedfile:
                        fopen = open(o_path + '\\' + path_read_file, 'r')
                        read = fopen.read(100)
                        textosend = textosend + '\n\t' + read
                        openedfile = True
                        writer.write(textosend.encode())
                        await writer.drain()
                        continue

                    # Continue reading if the file is already open.
                    else:
                        readmore = fopen.read(100)
                        textosend = textosend + '\n\t' + readmore
                        writer.write(textosend.encode())
                        await writer.drain()
                        continue
            else:
                print("[SYSTEM] Not possible to read a folder in here.\n")
                writer.write("[SYSTEM] Not possible to read a folder in here.\n".encode())
                await writer.drain()

        # If the next commands is command is not read_file, the file will close.
        else:
            if openedfile:
                openedfile = False
                fopen.close()
            if message == 'read_file':
                writer.write('[*] You have to log in first. '.encode())
                await writer.drain()
                continue

        if message == 'register':
            if not logged:
                registered = False
                writer.write('[*] Username: '.encode())
                await writer.drain()
                username = await reader.read(2048)
                username = username.decode().strip()

                # This for loop looks for users in the directory.
                for users in os.listdir(os.getcwd()):
                    if users == username:
                        registered = True

                if not registered:

                    # If the user is not registered, the password is requested.
                    writer.write('[*] Password: '.encode())
                    await writer.drain()
                    password = await reader.read(2048)
                    password = password.decode().strip()

                    # Checking for (not) empty username or password.
                    if len(username) == 0:
                        if len(password) == 0:
                            print("[!] User or password cannot be empty.\n")
                            writer.write("[!] User or password cannot be empty.\n".encode())
                            await writer.drain()
                    else:
                        register(username, password)
                        writer.write("[*] Register completed.".encode())
                        username = None
                        await writer.drain()
                        continue
                else:
                    writer.write('[*] User already registered. '.encode())
                    await writer.drain()
                    continue
            else:
                writer.write(f"[!] You cannot register if you are already "
                             f"logged, {username}.".encode())
                await writer.drain()
                continue

        elif message == 'login':
            if not logged:

                # Request username and password.
                writer.write('[*] Username: '.encode())
                await writer.drain()
                username = await reader.read(2048)
                username = username.decode().strip()
                writer.write('[*] Password: '.encode())
                await writer.drain()
                password = await reader.read(2048)
                password = password.decode().strip()

                # Checking for (not) empty username or password.
                if len(username) == 0:
                    if len(password) == 0:
                        print("[!] User or password cannot be empty\n")
                        writer.write("[!] User or password cannot be empty\n".encode())
                        await writer.drain()
                else:
                    path = username + '\\'
                    login_info = login(o_path, username, password)
                    original_path = login_info[0]
                    logged = login_info[1]
                    alert_msg = login_info[2]

                    # If there is not alert message, it means the login was correct.
                    if len(alert_msg) == 0:
                        print("[!] Login correct.\n")
                        writer.write("[!] Login correct.\n".encode())
                        await writer.drain()
                    else:
                        print(f"[!] {alert_msg}\n")
                        writer.write(f"[!] {alert_msg}\n".encode())
                        username = None
            else:
                writer.write(f"[!] You are already logged, {username}.".encode())
                await writer.drain()
                continue

        elif message == 'create_folder':
            if logged:

                # Server asks for the folder name.
                writer.write('[*] Folder name: '.encode())
                await writer.drain()
                folder_name = await reader.read(2048)
                folder_name = folder_name.decode().strip()
                if safe_path(o_path, path, folder_name, username):
                    path_new_folder = path + folder_name + '\\'
                    # Security check to prevent path traversal.
                    if os.path.normpath(o_path + '\\' + username + '\\' + path_new_folder).startswith(o_path + "\\" + username):
                        if not create_folder(o_path, logged, path_new_folder):
                            writer.write('[!] Folder creation not possible'.encode())
                            await writer.drain()
                            continue
                        else:
                            writer.write('[*] Folder created correctly'.encode())
                            continue

                    # Attempt to create a folder in a restricted area.
                    else:
                        print("[SYSTEM] Not possible to create a folder in here.")
                        writer.write("[SYSTEM] Not possible to create a folder in here.".encode())
                        await writer.drain()
                else:
                    print("[SYSTEM] Not possible to create a folder in here.")
                    writer.write("[SYSTEM] Not possible to create a folder in here.".encode())
                    await writer.drain()
            else:
                print("[!] You have to log in first.")
                writer.write("[!] You have to log in first.".encode())
                await writer.drain()
                continue

        elif message == 'write_file':
            if logged:

                # Server asks for the file name.
                writer.write('[*] File name: '.encode())
                await writer.drain()
                file_name = await reader.read(2048)
                file_name = file_name.decode().strip()
                # Server asks for the text to write inside of the file.
                writer.write('[*] What do you want to write? '.encode())
                await writer.drain()
                message = await reader.read(2048)
                message = message.decode().strip()
                if safe_path(o_path, path, file_name, username):
                    path_to_write = path + file_name
                    print('write_file:', path_to_write)
                    if os.path.normpath(o_path + '\\' + username + '\\' + path_to_write).startswith(o_path + "\\" + username):
                        if not write_file(o_path, path_to_write, logged, message):
                            print("[!] Not possible to write.")
                            writer.write("[!] Not possible to write.".encode())
                            await writer.drain()
                        else:
                            print("[!] File written correctly.")
                            writer.write("[!] File written correctly.".encode())
                            await writer.drain()
                            continue
                else:
                    print("[!] Not possible to write.")
                    writer.write("[!] Not possible to write.".encode())
                    await writer.drain()
            else:
                print("[!] You have to log in first.")
                writer.write("[!] You have to log in first.".encode())
                await writer.drain()
                continue

        elif message == 'change_folder':
            if logged:

                # Server ask for the name of the folder that already exists.
                writer.write('[*] Folder name: '.encode())
                await writer.drain()
                new_folder = await reader.read(2048)
                new_folder = new_folder.decode().strip()
                if safe_path(o_path, path, new_folder, username):
                    path2 = path + new_folder + '\\'
                    # Security check against path traversal.
                    if os.path.normpath(o_path + '\\' + username + '\\' + path2).startswith(o_path):
                        if change_folder(o_path, path2, logged):
                            writer.write(f"[!] Directory changed to folder {new_folder}.".encode())
                            path = path + new_folder + '\\'
                            await writer.drain()
                            continue
                        else:
                            writer.write(f"[!] Folder '{new_folder}' does not exist.".encode())
                            await writer.drain()
                            continue
                    else:
                        print("[!] Not possible to change folder.")
                        writer.write("[!] Not possible to change folder.".encode())
                        await writer.drain()
                else:
                    print("[!] Not possible to change folder.")
                    writer.write("[!] Not possible to change folder.".encode())
                    await writer.drain()
            else:
                print("[!] You have to log in first.")
                writer.write("[!] You have to log in first.".encode())
                await writer.drain()
                continue

        # Extra command useful to know if the user is logged or not.
        elif message == 'id':
            if username:
                writer.write(f'[#] You are {username} '.encode())
            else:
                writer.write('[#] You are not logged in '.encode())
                continue

        elif message == 'commands':
            await writer.drain()
            continue

        elif message == 'list':
            if logged:

                # Lists all the files and folder in the current directory.
                send = listt(logged, username, o_path, path)
                if send == None:
                    send = "FILE\t->\tDATE\t->\tSIZE"
                writer.write(send.encode())
                # writer.write(listt(logged, username).encode())
                await writer.drain()
                continue
            else:
                print("[!] You have to log in first.")
                writer.write("[!] You have to log in first.".encode())
                await writer.drain()
                continue

        else:
            writer.write("[*] Type 'commands' if you are lost.".encode())
            await writer.drain()
            continue

    print(f"[#] {addr}Closed the connection")
    writer.close()


async def main():
    """
    Main function of the program, opens the server in localhost and port 8088
    and waits for client connections.
    """
    server = await asyncio.start_server(
        handle_echo, '127.0.0.1', 8088)

    addr = server.sockets[0].getsockname()
    print(f'[*] Serving on {addr}')

    async with server:
        await server.serve_forever()


asyncio.run(main())
