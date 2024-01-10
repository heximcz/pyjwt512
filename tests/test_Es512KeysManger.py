import os
import unittest
import tempfile
from pyjwt512.Es512KeysManger import Es512KeysManger

class TestEs512KeysManger(unittest.TestCase):

    def setUp(self):
        self.key_manager = Es512KeysManger()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        # Clean up any created temporary files
        for file in os.listdir(self.temp_dir):
            os.remove(os.path.join(self.temp_dir, file))
        os.rmdir(self.temp_dir)

    def test_generate_new_keys(self):
        self.key_manager.generate_new_keys()
        self.assertIsNotNone(self.key_manager.get_priv_cert())
        self.assertIsNotNone(self.key_manager.get_pub_cert())

    def test_save_and_load_keys(self):
        self.key_manager.generate_new_keys()
        self.key_manager.save_new_keys(self.temp_dir)

        # Check if the files exist
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, self.key_manager.get_root_filename() + '.pem')))
        self.assertTrue(os.path.exists(os.path.join(self.temp_dir, self.key_manager.get_root_filename() + '-public.pem')))

        # Test loading keys
        new_manager = Es512KeysManger()
        self.assertTrue(new_manager.load_keys(self.temp_dir, filename=""))
        self.assertEqual(new_manager.get_priv_cert(), new_manager.get_priv_cert())
        self.assertEqual(new_manager.get_pub_cert(), new_manager.get_pub_cert())

        filename = new_manager.get_root_filename()

        # Test loading existing keys
        new_manager2 = Es512KeysManger()
        self.assertTrue(new_manager2.load_keys(self.temp_dir, filename=filename))
        self.assertEqual(new_manager2.get_priv_cert(), new_manager.get_priv_cert())
        self.assertEqual(new_manager2.get_pub_cert(), new_manager.get_pub_cert())
