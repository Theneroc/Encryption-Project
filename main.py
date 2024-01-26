import sys

from PyQt5 import QtGui
from PyQt5 import QtWidgets
from PyQt5.QtCore import QSize
from PyQt5.QtWidgets import QDialog, QApplication, QFileDialog, QMessageBox, QComboBox, QPlainTextEdit, QLineEdit
from PyQt5.uic import loadUi

import BlockChaining
from Ciphers import Columnar, Ceaser, EnhancedCaeser, EnhancedColumnar


class MainScreen(QDialog):
    useChaining = False
    currentFile: str
    currentOutputDestination: str

    def __init__(self):
        super(MainScreen, self).__init__()
        loadUi("UI Files\\MainScreen.ui", self)
        widget.setFixedSize(QSize(1116, 880))

        self.btnEncrypt.clicked.connect(self.Encrypt)
        self.btnDecrypt.clicked.connect(self.Decrypt)
        self.btnSelectFile.clicked.connect(self.SelectFile)
        self.btnSelectOutputDestination.clicked.connect(self.SelectOutputDestination)
        self.txtAdvanced.mousePressEvent = self.Advanced
        self.taSignature.setPlainText("")  # placeholder bug
        self.btnClear.clicked.connect(self.ClearEverything)

        self.currentFile = ""
        self.currentOutputDestination = ""

    def ClearEverything(self):
        self.taPlainText.setPlainText("")
        self.taCipherText.setPlainText("")
        self.taSignature.setPlainText("")

        self.tfKey.setText("")

        self.currentFile = ""
        self.currentOutputDestination = ""

        self.txtFileChosen.setText("")
        self.txtOutputDestination.setText("")







    def Advanced(self, *arg, **kwargs):
        if (widget.height() > 880):
            widget.setFixedSize(QSize(1116, 880))
        else:
            widget.setFixedSize(QSize(1116, 992))

    def Encrypt(self):

        useChaining = self.chkBlockChain.isChecked()
        # fileSignature =self.taSignature.toPlainText()

        plainText: str
        if len(self.currentFile) != 0:
            with open(self.currentFile, "r") as f:
                plainText = f.read()
        else:
            plainText = self.taPlainText.toPlainText()

        if self.cmbEncryptionTechniques.currentIndex() == 0:  # Caeser Cipher
            key = self.tfKey.text()
            if (key.isnumeric()):
                if useChaining:
                    cipherText, fileSignature = BlockChaining.encryptCaeser(plainText, int(key))
                    if cipherText is None:
                        msg = QMessageBox()
                        msg.setIcon(QMessageBox.Warning)

                        msg.setText("The key you have entered is not valid!\nMust Be -25 - 25")

                        msg.setWindowTitle("Invalid Key")

                        msg.setStandardButtons(QMessageBox.Ok)
                        retval = msg.exec_()
                    else:
                        if len(self.txtFileChosen.text()) != 0 and len(self.txtOutputDestination.text()) != 0:
                            self.WriteToFile(cipherText)
                            self.taSignature.setPlainText(fileSignature.decode('utf-8'))
                        else:
                            self.taCipherText.setPlainText(cipherText)
                            self.taSignature.setPlainText(fileSignature.decode('utf-8'))
                else:
                    cipherText = Ceaser.encrypt(plainText, key)
                    if cipherText is None:
                        msg = QMessageBox()
                        msg.setIcon(QMessageBox.Warning)

                        msg.setText("The key you have entered is not valid!\nMust Be -25 - 25")

                        msg.setWindowTitle("Invalid Key")

                        msg.setStandardButtons(QMessageBox.Ok)
                        retval = msg.exec_()
                    else:
                        if len(self.txtFileChosen.text()) != 0 and len(self.txtOutputDestination.text()) != 0:
                            self.WriteToFile(cipherText)
                        else:
                            self.taCipherText.setPlainText(cipherText)


            else:
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Warning)

                msg.setText("The key you have entered is not valid!")

                msg.setWindowTitle("Invalid Key")

                msg.setStandardButtons(QMessageBox.Ok)
                retval = msg.exec_()

        if self.cmbEncryptionTechniques.currentIndex() == 1:  # Columnar
            key = self.tfKey.text()
            if useChaining:

                cipherText, fileSignature = BlockChaining.encryptColumnar(plainText, int(key))

                if cipherText is None:
                    msg = QMessageBox()
                    msg.setIcon(QMessageBox.Warning)

                    msg.setText("The key you have entered is not valid!\nMust Be a number")

                    msg.setWindowTitle("Invalid Key")

                    msg.setStandardButtons(QMessageBox.Ok)
                    retval = msg.exec_()
                else:
                    if len(self.txtFileChosen.text()) != 0 and len(self.txtOutputDestination.text()) != 0:
                        self.WriteToFile(cipherText)
                        self.taSignature.setPlainText(fileSignature.decode('utf-8'))
                    else:
                        self.taCipherText.setPlainText(cipherText)
                        self.taSignature.setPlainText(fileSignature.decode('utf-8'))

            else:
                cipherText = Columnar.encrypt(plainText, key)
                if cipherText is None:
                    msg = QMessageBox()
                    msg.setIcon(QMessageBox.Warning)

                    msg.setText("The key you have entered is not valid!\nMust Be numbers between separated by ,")

                    msg.setWindowTitle("Invalid Key")

                    msg.setStandardButtons(QMessageBox.Ok)
                    retval = msg.exec_()
                else:
                    if len(self.txtFileChosen.text()) != 0 and len(self.txtOutputDestination.text()) != 0:
                        self.WriteToFile(cipherText)
                    else:
                        self.taCipherText.setPlainText(cipherText)

        if self.cmbEncryptionTechniques.currentIndex() == 2:  # Enhanced Caeser
            key = self.tfKey.text()
            if (key.isnumeric()):
                if useChaining:
                    cipherText, fileSignature = BlockChaining.encryptEnhancedCaeser(plainText, int(key))

                    if cipherText is None:
                        msg = QMessageBox()
                        msg.setIcon(QMessageBox.Warning)

                        msg.setText("The key you have entered is not valid!")

                        msg.setWindowTitle("Invalid Key")

                        msg.setStandardButtons(QMessageBox.Ok)
                        retval = msg.exec_()

                    if len(self.txtFileChosen.text()) != 0 and len(self.txtOutputDestination.text()) != 0:
                        self.WriteToFile(cipherText)
                        self.taSignature.setPlainText(fileSignature.decode('utf-8'))
                    else:
                        self.taCipherText.setPlainText(cipherText)
                        self.taSignature.setPlainText(fileSignature.decode('utf-8'))
                else:
                    cipherText = EnhancedCaeser.encrypt(plainText, int(key))
                    if cipherText is None:
                        msg = QMessageBox()
                        msg.setIcon(QMessageBox.Warning)

                        msg.setText("The key you have entered is not valid!")

                        msg.setWindowTitle("Invalid Key")

                        msg.setStandardButtons(QMessageBox.Ok)
                        retval = msg.exec_()
                    else:
                        if len(self.txtFileChosen.text()) != 0 and len(self.txtOutputDestination.text()) != 0:
                            self.WriteToFile(cipherText)
                        else:
                            self.taCipherText.setPlainText(cipherText)
            else:
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Warning)

                msg.setText("The key you have entered is not valid!")

                msg.setWindowTitle("Invalid Key")

                msg.setStandardButtons(QMessageBox.Ok)
                retval = msg.exec_()

        if self.cmbEncryptionTechniques.currentIndex() == 3:  # Enhanced Columnar
            key = self.tfKey.text()
            if useChaining:

                cipherText, fileSignature = BlockChaining.encryptEnhancedColumnar(plainText, int(key))

                if cipherText is None:
                    msg = QMessageBox()
                    msg.setIcon(QMessageBox.Warning)

                    msg.setText("The key you have entered is not valid!\nMust Be a number")

                    msg.setWindowTitle("Invalid Key")

                    msg.setStandardButtons(QMessageBox.Ok)
                    retval = msg.exec_()
                else:
                    if len(self.txtFileChosen.text()) != 0 and len(self.txtOutputDestination.text()) != 0:
                        self.WriteToFile(cipherText)
                        self.taSignature.setPlainText(fileSignature.decode('utf-8'))
                    else:
                        self.taCipherText.setPlainText(cipherText)
                        self.taSignature.setPlainText(fileSignature.decode('utf-8'))
            else:
                keyLen = int(key)%32
                if keyLen<4:
                    keyLen= 4

                cipherText = EnhancedColumnar.encrypt(plainText, int(key),keyLen)


                if cipherText is None:
                    msg = QMessageBox()
                    msg.setIcon(QMessageBox.Warning)

                    msg.setText("The key you have entered is not valid!\nMust Be a number")

                    msg.setWindowTitle("Invalid Key")

                    msg.setStandardButtons(QMessageBox.Ok)
                    retval = msg.exec_()
                else:
                    if len(self.txtFileChosen.text()) != 0 and len(self.txtOutputDestination.text()) != 0:
                        self.WriteToFile(cipherText)
                    else:
                        self.taCipherText.setPlainText(cipherText)

    def Decrypt(self):
        useChaining = self.chkBlockChain.isChecked()

        if len(self.currentFile) != 0:
            with open(self.currentFile, "r") as f:
                cipherText = f.read()
        else:
            cipherText = self.taPlainText.toPlainText()

        signature: bytes
        signature = self.taSignature.toPlainText().encode('utf-8')
        # print(signature)

        if self.cmbEncryptionTechniques.currentIndex() == 0:  # Ceaser
            key = self.tfKey.text()

            if (key.isnumeric()):
                if useChaining:
                    if len(signature) != 64:
                        msg = QMessageBox()
                        msg.setIcon(QMessageBox.Warning)

                        msg.setText("The signature you have entered is not valid!")

                        msg.setWindowTitle("Invalid Signature!")

                        msg.setStandardButtons(QMessageBox.Ok)
                        retval = msg.exec_()
                    else:

                        plainText = BlockChaining.decryptCaeser(cipherText, int(key), signature)

                        if plainText is None:
                            msg = QMessageBox()
                            msg.setIcon(QMessageBox.Warning)

                            msg.setText("The key you have entered is not valid!")

                            msg.setWindowTitle("Invalid Key")

                            msg.setStandardButtons(QMessageBox.Ok)
                            retval = msg.exec_()
                        else:

                            if len(self.txtFileChosen.text()) != 0 and len(self.txtOutputDestination.text()) != 0:
                                self.WriteToFile(plainText)
                            else:
                                self.taCipherText.setPlainText(plainText)



                else:
                    plainText = Ceaser.decrypt(cipherText, key)

                    if plainText is None:
                        msg = QMessageBox()
                        msg.setIcon(QMessageBox.Warning)

                        msg.setText("The key you have entered is not valid!")

                        msg.setWindowTitle("Invalid Key")

                        msg.setStandardButtons(QMessageBox.Ok)
                        retval = msg.exec_()
                    else:
                        if len(self.txtFileChosen.text()) != 0 and len(self.txtOutputDestination.text()) != 0:
                            self.WriteToFile(plainText)
                        else:
                            self.taCipherText.setPlainText(plainText)


            else:

                msg = QMessageBox()
                msg.setIcon(QMessageBox.Warning)

                msg.setText("The key you have entered is not valid!")

                msg.setWindowTitle("Invalid Key")

                msg.setStandardButtons(QMessageBox.Ok)
                retval = msg.exec_()

        if self.cmbEncryptionTechniques.currentIndex() == 1:  # Columnar
            key = self.tfKey.text()
            if useChaining:
                plainText = BlockChaining.decryptColumnar(cipherText, int(key), signature)
                if plainText is None:
                    msg = QMessageBox()
                    msg.setIcon(QMessageBox.Warning)

                    msg.setText("The key you have entered is not valid!")

                    msg.setWindowTitle("Invalid Key")

                    msg.setStandardButtons(QMessageBox.Ok)
                    retval = msg.exec_()
                else:
                    if len(self.txtFileChosen.text()) != 0 and len(self.txtOutputDestination.text()) != 0:
                        self.WriteToFile(plainText)
                    else:
                        self.taCipherText.setPlainText(plainText)
            else:
                plainText = Columnar.decrypt(cipherText, key)

                if plainText is None:
                    msg = QMessageBox()
                    msg.setIcon(QMessageBox.Warning)

                    msg.setText("The key you have entered is not valid!\nShould be numbers seperated by \",\" ")

                    msg.setWindowTitle("Invalid Key")

                    msg.setStandardButtons(QMessageBox.Ok)
                    retval = msg.exec_()
                else:
                    if len(self.txtFileChosen.text()) != 0 and len(self.txtOutputDestination.text()) != 0:
                        self.WriteToFile(plainText)
                    else:
                        self.taCipherText.setPlainText(plainText)

        if self.cmbEncryptionTechniques.currentIndex() == 2:  # Enhanced Ceaser
            key = self.tfKey.text()

            if (key.isnumeric()):
                if useChaining:
                    if len(signature) != 64:
                        msg = QMessageBox()
                        msg.setIcon(QMessageBox.Warning)

                        msg.setText("The signature you have entered is not valid!")

                        msg.setWindowTitle("Invalid Signature!")

                        msg.setStandardButtons(QMessageBox.Ok)
                        retval = msg.exec_()
                    else:

                        plainText = BlockChaining.decryptEnhancedCaeser(cipherText, int(key), signature)

                        if plainText is None:
                            msg = QMessageBox()
                            msg.setIcon(QMessageBox.Warning)

                            msg.setText("The key you have entered is not valid!")

                            msg.setWindowTitle("Invalid Key")

                            msg.setStandardButtons(QMessageBox.Ok)
                            retval = msg.exec_()
                        else:
                            if len(self.txtFileChosen.text()) != 0 and len(self.txtOutputDestination.text()) != 0:
                                self.WriteToFile(plainText)
                            else:
                                self.taCipherText.setPlainText(plainText)



                else:
                    plainText = EnhancedCaeser.decrypt(cipherText, int(key))

                    if plainText is None:
                        msg = QMessageBox()
                        msg.setIcon(QMessageBox.Warning)

                        msg.setText("The key you have entered is not valid!")

                        msg.setWindowTitle("Invalid Key")

                        msg.setStandardButtons(QMessageBox.Ok)
                        retval = msg.exec_()
                    else:
                        if len(self.txtFileChosen.text()) != 0 and len(self.txtOutputDestination.text()) != 0:
                            self.WriteToFile(plainText)
                        else:
                            self.taCipherText.setPlainText(plainText)


            else:

                msg = QMessageBox()
                msg.setIcon(QMessageBox.Warning)

                msg.setText("The key you have entered is not valid!")

                msg.setWindowTitle("Invalid Key")

                msg.setStandardButtons(QMessageBox.Ok)
                retval = msg.exec_()

        if self.cmbEncryptionTechniques.currentIndex() == 3:  # Enhanced Columnar
            key = self.tfKey.text()
            if useChaining:
                plainText = BlockChaining.decryptEnhancedColumnar(cipherText, int(key), signature)
                if plainText is None:
                    msg = QMessageBox()
                    msg.setIcon(QMessageBox.Warning)

                    msg.setText("The key you have entered is not valid!")

                    msg.setWindowTitle("Invalid Key")

                    msg.setStandardButtons(QMessageBox.Ok)
                    retval = msg.exec_()
                else:
                    if len(self.txtFileChosen.text()) != 0 and len(self.txtOutputDestination.text()) != 0:
                        self.WriteToFile(plainText)
                    else:
                        self.taCipherText.setPlainText(plainText)
            else:
                keyLen = int(key)%32
                if keyLen<4:
                    keyLen= 4

                plainText = EnhancedColumnar.decrypt(cipherText, int(key),keyLen)

                if plainText is None:
                    msg = QMessageBox()
                    msg.setIcon(QMessageBox.Warning)

                    msg.setText("The key you have entered is not valid!\nShould be numbers seperated by \",\" ")

                    msg.setWindowTitle("Invalid Key")

                    msg.setStandardButtons(QMessageBox.Ok)
                    retval = msg.exec_()
                else:
                    if len(self.txtFileChosen.text()) != 0 and len(self.txtOutputDestination.text()) != 0:
                        self.WriteToFile(plainText)
                    else:
                        self.taCipherText.setPlainText(plainText)
    def SelectFile(self):
        filter = "Text files (*.txt)"
        messageFileName = QFileDialog.getOpenFileNames(self, 'Get Message File', './', filter=filter)

        if len(messageFileName[0]) != 0:
            self.txtFileChosen.setText(messageFileName[0][0].split("/")[-1])
            self.currentFile = messageFileName[0][0]

    def WriteToFile(self,textToWrite:str):
        with open(self.currentOutputDestination, 'w') as f:
            f.write(textToWrite)

    def SelectOutputDestination(self):
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Set Output Destination", './', "Text File (*.txt")
        if len(filename) != 0:
            self.txtOutputDestination.setText(filename.split("/")[-1])
            self.currentOutputDestination = filename


app = QApplication(sys.argv)
widget = QtWidgets.QStackedWidget()  # Create an instance of QStackedWidget

mainMenuPage = MainScreen()
widget.addWidget(mainMenuPage)  # Add the MainMenu page to the stack
# widget 0
widget.setWindowTitle("Goon Squad")

widget.show()
sys.exit(app.exec_())
