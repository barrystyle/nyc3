// Copyright (c) 2011-2014 The NYC3 Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_nyc3addressvalidator_H
#define BITCOIN_QT_nyc3addressvalidator_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class NYC3AddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit NYC3AddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

/** NYC3 address widget validator, checks for a valid bitcoin address.
 */
class NYC3AddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit NYC3AddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

#endif // BITCOIN_QT_nyc3addressvalidator_H
