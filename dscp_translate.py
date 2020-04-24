
# these values are found from RFC 4595
# https://tools.ietf.org/html/rfc4594#section-1.4.4
def lookup(n):
    if n == 0b110000:
        return "CS6 - Network Routing"
    elif n == 0b10100:
        return "CS5 - IP Telephony signaling"
    elif n == 0b100000:
        return "CS4 - Video Conferencing and Interactive gaming"
    elif n == 0b011000:
        return "CS3 - Broadcast TV & live events"
    elif n == 0b010000:
        return "CS2 - OAM&P"
    elif n == 0b001000:
        return "CS1 - No BW assurance"
    elif n == 0b000000:
        return "DF - Undifferentiated application"
    elif n == 0b001010:
        return "AF11 - Store and forward"
    elif n == 0b001100:
        return "AF12 - Store and forward"
    elif n == 0b001110:
        return "AF13 - Store and forward"
    elif n == 0b010010:
        return "AF21 - Client/Server transaction"
    elif n == 0b010100:
        return "AF22 - Client/Server transaction"
    elif n == 0b010110:
        return "AF23 - Client/Server transaction"
    elif n == 0b011010:
        return "AF31 - Streaming audio/video"
    elif n == 0b011100:
        return "AF32 - Streaming audio/video"
    elif n == 0b011110:
        return "AF33 - Streaming audio/video"
    elif n == 0b100010:
        return "AF41 - H.323/V2 video conferencing"
    elif n == 0b100100:
        return "AF42 - H.323/V2 video conferencing"
    elif n == 0b100110:
        return "AF43 - H.323/V2 video conferencing"
    elif n == 0b101110:
        return "EF - IP Telephony bearer"
    else:
        return "Unknown"
