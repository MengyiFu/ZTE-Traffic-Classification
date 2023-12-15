"""
@Time    : 2022/6/23 14:47
-------------------------------------------------
@Author  : sailorlee(lizeyi)
@email   : sailorlee31@gmail.com
-------------------------------------------------
@FileName: options.py
@Software: PyCharm
"""
import argparse
import os


class Options():

    def __init__(self):
        self.parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        self.parser.add_argument('--label',default='label',help='data class labels.')
        # self.parser.add_argument('--server_ip', default='sh-cynosdbmysql-grp-5dmxbh9a.sql.tencentcdb.com', help='server ip addr.')
        # self.parser.add_argument('--server_port', default=22, help='connect server port.')
        # self.parser.add_argument('--server_username', default='runtrend', help='the name that server log in.')
        # self.parser.add_argument('--server_password', default='3edc$RFV%TGB', help='the password that server log in.')

        self.parser.add_argument('--csv_path', default='./csv/', help='the csv dataset file path.')

        self.parser.add_argument('--mysql_ip', default='sh-cynosdbmysql-grp-5dmxbh9a.sql.tencentcdb.com', help='mysql server ip addr.')
        self.parser.add_argument('--mysql_port', default=26618, help='connect mysql port.')
        self.parser.add_argument('--mysql_username', default='runtrend', help='the username that mysql log in.')
        self.parser.add_argument('--mysql_password', default='4rfv*UHB', help='the password that mysql log in.')
        self.parser.add_argument('--databaseName', default='flowfeature', help='the name that database log in.')
        self.parser.add_argument('--tableName', default='APflowfeature', help='the name of table.')
        self.opt = None

    def parse(self) -> object:
        """ Parse Arguments.
        """

        self.opt = self.parser.parse_args()
        args = vars(self.opt)



        return self.opt