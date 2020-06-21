#ifndef SERVER_H
#define SERVER_H

#include <QtCore>
#include <QtNetwork>

#include <vector>

QT_BEGIN_NAMESPACE
class DtlsServer : public QObject
{
    Q_OBJECT

public:
    DtlsServer();
    ~DtlsServer();
    bool listen(const QHostAddress &address, quint16 port);
    bool isListening() const;
    void close();

signals:
    void errorMessage(const QString &message);
    void warningMessage(const QString &message);
    void infoMessage(const QString &message);
    void datagramReceived(const QString &peerInfo, const QByteArray &cipherText,
                          const QByteArray &plainText);

private slots:
    void readyRead();
    void pskRequired(QSslPreSharedKeyAuthenticator *auth);

private:
    void handleNewConnection(const QHostAddress &peerAddress, quint16 peerPort,
                             const QByteArray &clientHello);
    using DtlsConnection = QSharedPointer<QDtls>;
    void doHandshake(DtlsConnection newConnection, const QByteArray &clientHello);
    void decryptDatagram(DtlsConnection connection, const QByteArray &clientMessage);
    void shutdown();

    bool listening = false;
    QUdpSocket serverSocket;
    QSslConfiguration serverConfiguration;
    QDtlsClientVerifier cookieSender;
    QVector<DtlsConnection> knownClients;

    Q_DISABLE_COPY(DtlsServer)
};

QT_END_NAMESPACE

#endif // SERVER_H
