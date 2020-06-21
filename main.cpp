#include <QApplication>

#include "mainwindow.h"

int main(int argc, char *argv[])
{
    QT_USE_NAMESPACE

    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
