import sys

from PyQt5 import QtGui
from PyQt5 import QtWidgets
from PyQt5.QtCore import QSize
from PyQt5.QtWidgets import QDialog, QApplication, QFileDialog, QMessageBox, QComboBox, QPlainTextEdit, QLineEdit
from PyQt5.uic import loadUi

import BlockChaining
from Ciphers import Columnar

class MainScreen(QDialog):

    useChaining = False
    def __init__(self):
        super(MainScreen, self).__init__()
        loadUi("UI Files\\MainScreen.ui", self)
        widget.setFixedSize(QSize(1116, 880))

        self.btnEncrypt.clicked.connect(self.Encrypt)
        self.btnDecrypt.clicked.connect(self.Decrypt)
        self.btnSelectFile.clicked.connect(self.SelectFile)
        self.btnSelectOutputDestination.clicked.connect(self.SelectOutputDestination)
        self.txtAdvanced.mousePressEvent = self.Advanced
        self.taSignature.setPlainText("")#placeholder bug

    def Advanced(self,*arg, **kwargs):
        if(widget.height()>880):
            widget.setFixedSize(QSize(1116, 880))
        else:
            widget.setFixedSize(QSize(1116, 992))


    def Encrypt(self):

        useChaining = self.chkBlockChain.isChecked()
        fileSignature =   self.taSignature.toPlainText()

        if self.cmbEncryptionTechniques.currentIndex() == 0:
            key = self.tfKey.text()
            if (key.isnumeric()):
                cipherText = BlockChaining.encryptCaeser(self.taPlainText.toPlainText(),key)
                self.taCipherText.setPlainText(cipherText)
            else:
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Warning)

                msg.setText("The key you have entered is not valid!")

                msg.setWindowTitle("Invalid Key")

                msg.setStandardButtons(QMessageBox.Ok)
                retval = msg.exec_()

        if self.cmbEncryptionTechniques.currentIndex() == 1:
            key = self.tfKey.text()
            if (key.isnumeric()):
                cipherText = BlockChaining.encryptColumnar(key,self.taPlainText.toPlainText())
                self.taCipherText.setPlainText(cipherText)
            else:
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Warning)

                msg.setText("The key you have entered is not valid!")

                msg.setWindowTitle("Invalid Key")

                msg.setStandardButtons(QMessageBox.Ok)
                retval = msg.exec_()



    def Decrypt(self):

        useChaining = self.chkBlockChain.isChecked()

        if self.cmbEncryptionTechniques.currentIndex() == 0:
            key = self.tfKey.text()

            if (key.isnumeric()):
                plainText = BlockChaining.decryptCaeser(key, int(self.taPlainText.toPlainText()))
                self.taCipherText.setPlainText(plainText)
            else:

                msg = QMessageBox()
                msg.setIcon(QMessageBox.Warning)

                msg.setText("The key you have entered is not valid!")

                msg.setWindowTitle("Invalid Key")

                msg.setStandardButtons(QMessageBox.Ok)
                retval = msg.exec_()

        if self.cmbEncryptionTechniques.currentIndex() == 1:
            key = self.tfKey.text()
            if (key.isnumeric()):
                plainText = BlockChaining.decryptColumnar(key, self.taPlainText.toPlainText())
                self.taCipherText.setPlainText(plainText)
            else:
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Warning)

                msg.setText("The key you have entered is not valid!")

                msg.setWindowTitle("Invalid Key")

                msg.setStandardButtons(QMessageBox.Ok)
                retval = msg.exec_()


    def SelectFile(self):
        filter = "Text files (*.txt)"
        messageFileName = QFileDialog.getOpenFileNames(self, 'Get Message File', './', filter=filter)

        if len(messageFileName[0]) != 0:
            self.txtFileChosen.setText(messageFileName[0][0].split("/")[-1])

        


    def SelectOutputDestination(self):
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Set Output Destination", './', "Text File (*.txt")
        if len(filename) != 0:
            self.txtOutputDestination.setText(filename.split("/")[-1])


app = QApplication(sys.argv)
widget = QtWidgets.QStackedWidget()  # Create an instance of QStackedWidget

mainMenuPage = MainScreen()
widget.addWidget(mainMenuPage)  # Add the MainMenu page to the stack
#widget 0
widget.setWindowTitle("Goon Squad")




widget.show()
sys.exit(app.exec_())