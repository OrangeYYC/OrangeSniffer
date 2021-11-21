#ifndef PRASERFACTORY_H
#define PRASERFACTORY_H

#include "ethpraser.h"

static AbstractPraser* create(u_short protocol, QString base = "")
{
    if (base == "")
        return new EthPraser;

    if (base == "Ethernet II") {
        switch (protocol) {
        case 0x0800:
            return nullptr;
            break;
        default:
            return nullptr;
            break;
        }
    }
    return nullptr;
}

#endif
