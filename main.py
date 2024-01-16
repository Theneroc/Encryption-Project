import sys

from PyQt5 import QtGui
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog, QApplication, QFileDialog, QMessageBox, QComboBox, QPlainTextEdit, QLineEdit
from PyQt5.uic import loadUi

from Ciphers import Columnar

class MainScreen(QDialog):
    def __init__(self):
        super(MainScreen, self).__init__()
        loadUi("UI Files\\MainScreen.ui", self)
        self.setFixedHeight(847)
        self.setFixedWidth(1116)
        self.btnEncrypt.clicked.connect(self.Encrypt)
        self.btnDecrypt.clicked.connect(self.Decrypt)
        self.btnSelectFile.clicked.connect(self.SelectFile)
        self.btnSelectOutputDestination.clicked.connect(self.SelectOutputDestination)

    def Encrypt(self):

        if self.cmbEncryptionTechniques.currentIndex() == 1:
            key = self.tfKey.text()
            if (Columnar.validateKey(key)):
                cipherText = Columnar.encrypt(key,self.taPlainText.toPlainText())
                self.taCipherText.setPlainText(cipherText)
            else:
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Warning)

                msg.setText("The key you have entered is not valid!")

                msg.setWindowTitle("Invalid Key")

                msg.setStandardButtons(QMessageBox.Ok)
                retval = msg.exec_()



    def Decrypt(self):
        if self.cmbEncryptionTechniques.currentIndex() == 1:
            key = self.tfKey.text()
            if (Columnar.validateKey(key)):
                plainText = Columnar.decrypt(key, self.taPlainText.toPlainText())
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
widget.setWindowTitle("Goon Squad")


widget.show()
sys.exit(app.exec_())