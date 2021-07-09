"""
Imports
"""
import asyncio
import unittest
import os
import server_v2

o_path = os.getcwd()


class Test(unittest.TestCase):
    """
    Main test class
    """
    async def setUp(self):
        """
        Defines de set up of the tests.
        """

        self.test_server = await asyncio.start_server(
            server_v2.handle_echo, '127.0.0.1', 8088)

        addr = self.test_server.sockets[0].getsockname()
        print(f'[*] Serving on address: {addr}')

        async with self.test_server:
            await self.test_server.serve_forever()

    def tearDown(self):
        """
        Finishes all the processes.
        """

        self.test_server.close()

    def correct_login(self):
        """
        Login into the server with correct credentials.
        """
        good_login_info = []
        good_login_info = server_v2.login(o_path, "user1", "user1")
        self.assertTrue(good_login_info[1])

    def false_login_credential(self):
        """
        Tries to log in the server using wrong credentials. Failure expected.
        """

        login_info = []
        try:
            login_info = server_v2.login(o_path, "user1", "user6543")
        except AssertionError:
            self.assertFalse(login_info[1], login_info[2])

    def change_folder(self):
        """
        Changes the folder directory as it was expected.
        """

        login_info = []
        folder_name = 'folder1'
        login_info = server_v2.login(o_path, 'user1', 'pass1')
        logged = login_info[1]
        path = login_info[0]

        if os.path.normpath(os.getcwd() + '\\' + folder_name).startswith(path):
            self.assertEqual(self, server_v2.change_folder(o_path, folder_name, logged))

    def change_folder_false(self):
        """
        Try to change the folder directory with a non-existent folder name.
        """

        login_info = []
        folder_name = 'folder1324'
        login_info = server_v2.login(o_path, 'user1', 'pass1')
        original_path = login_info[0]
        logged = login_info[1]

        if os.path.normpath(os.getcwd() + '\\' + folder_name).startswith(original_path):
            self.assertEqual(self, server_v2.change_folder(o_path, folder_name, logged))

    def change_folder_path_traversal(self):
        """
        Try to exploit path traversal vulnerability.
        """

        login_info = []
        folder_name = '../user1/userfolder1'
        login_info = server_v2.login(o_path, 'user2', 'pass2')
        original_path = login_info[0]
        logged = login_info[1]

        if os.path.normpath(os.getcwd() + '\\' + folder_name).startswith(original_path):
            self.assertEqual(self, server_v2.change_folder(o_path, folder_name, logged))
