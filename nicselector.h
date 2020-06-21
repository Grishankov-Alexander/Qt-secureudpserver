#ifndef NICSELECTOR_H
#define NICSELECTOR_H

#include <QDialog>
#include <QHostAddress>
#include <QVector>

QT_BEGIN_NAMESPACE
namespace Ui {
class NicSelector;
}
QT_END_NAMESPACE
QT_USE_NAMESPACE

class NicSelector : public QDialog
{
    Q_OBJECT

public:
    explicit NicSelector(QWidget *parent = nullptr);
    ~NicSelector();
    QHostAddress selectedIp() const;
    quint16 selectedPort() const;

private:
    Ui::NicSelector *ui = nullptr;
    QVector<QHostAddress> availableAddresses;
};

#endif // NICSELECTOR_H
