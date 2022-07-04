Variable Length list
====================
Definition
^^^^^^^^^^
As shown in the figure :numref:`tlv_variable_length` below, a **variable-length**
is encoded with:

 -  *Type* is the name of the variable to set.
 -  *Length* is the number of bytes of *Value*.
 -  *Value* is a concatenation of one null terminated string and byte streams.
    The byte streams is a suite of TLV encoded data.


.. figure:: figures/tlv_variable_length.png
   :align: center
   :name: tlv_variable_length

   TLV variable-length data

Example
^^^^^^^
The :numref:`tlv_variable_length_example` is the coding of key policies attribute
using a TLV variable-length specific coding. The key policies attribute tag type
is *POLICY*, the length is the number of bytes of the *Value* field that is
a variable-length list.

The example is encoding the key policies with usages:

a)	 Copiable (USAGE_COPY)
b)	 Encryption with restricted algorithms (USAGE_ENCRYPTION):

  -  Cipher with CBC mode with minimum tag length equal to 32 bits.
  -  Cipher Authenticated encryption with CCM mode without Tag length restriction (all tag lengths supported).

c)	 Signature generation with restricted algorithm (USAGE_SIGN):

  -  HMAC 256 bits.


.. table:: Example of TLV variable-length value
   :name: tlv_variable_length_example
   :align: left
   :widths: 35 15 50
   :width: 100%
   :class: wrap-table

   +---------------------+------------+-----------------------------------------+
   | **Type = POLICY**   | **Length** | **Value**                               |
   +=====================+============+=========================================+
   | 0x50 0x4F 0x4C 0x49 | 0x00 0x70  | 0x55 0x53 0x41 0x47 0x45 0x00 0x00 0x05 |
   | 0x43 0x59 0x00      |            | 0x43 0x4F 0x50 0x59 0x00 0x55 0x53 0x41 |
   |                     |            | 0x47 0x45 0x00 0x00 0x37 0x45 0x4E 0x43 |
   |                     |            | 0x52 0x59 0x20 0x54 0x00 0x41 0x4C 0x47 |
   |                     |            | 0x4F 0x00 0x00 0x1D 0x43 0x42 0x43 0x5F |
   |                     |            | 0x4E 0x4F 0x5F 0x50 0x41 0x44 0x44 0x49 |
   |                     |            | 0x4E 0x47 0x00 0x4D 0x49 0x4E 0x5F 0x4C |
   |                     |            | 0x45 0x4E 0x47 0x54 0x48 0x00 0x00 0x01 |
   |                     |            | 0x20 0x41 0x4C 0x47 0x4F 0x00 0x00 0x04 |
   |                     |            | 0x43 0x43 0x4D 0x00 0x55 0x53 0x41 0x47 |
   |                     |            | 0x45 0x00 0x00 0x1F 0x53 0x49 0x47 0x4E |
   |                     |            | 0x00 0x41 0x4C 0x47 0x4F 0x00 0x00 0x13 |
   |                     |            | 0x48 0x4D 0x41 0x43 0x00 0x48 0x41 0x53 |
   |                     |            | 0x48 0x00 0x00 0x07 0x53 0x48 0x41 0x32 |
   |                     |            | 0x35 0x36 0x00                          |
   +---------------------+------------+-----------------------------------------+


.. table:: Details of key policies example :numref:`tlv_variable_length_example`
   :name: tlv_detail_variable_length_example
   :align: left
   :widths: 8 15 10 16 18 10 23
   :width: 100%
   :class: wrap-table

   +----------+----------------------------------------------+----------------------------------------------+
   |          | **Usage**                                    | **Algo and parameter(s)**                    |
   +          +----------------+------------+----------------+----------------+------------+----------------+
   |          | **Type**       | **Length** | **Value**      | **Type**       | **Length** | **Value**      |
   +==========+================+============+================+================+============+================+
   | **Data** | USAGE          | 5          | COPY           |                                              |
   +----------+----------------+------------+----------------+                                              |
   | **Hex**  | 0x55 0x53 0x41 | 0x00 0x05  | 0x43 0x4F 0x50 |                                              |
   |          | 0x47 0x45 0x00 |            | 0x59 0x00      |                                              |
   +----------+----------------+------------+----------------+----------------+------------+----------------+
   | **Data** | USAGE          | 55         | ENCRYPT        | ALGO           | 29         | CBC_NO_PADDING |
   +----------+----------------+------------+----------------+----------------+------------+----------------+
   | **Hex**  | 0x55 0x53 0x41 | 0x00 0x37  | 0x45 0x4E 0x43 | 0x41 0x4C 0x47 | 0x00 0x1D  | 0x43 0x42 0x43 |
   |          | 0x47 0x45 0x00 |            | 0x52 0x59 0x50 | 0x4F 0x00      |            | 0x5F 0x4E 0x4F |
   |          |                |            | 0x54 0x00      |                |            | 0x5F 0x50 0x41 |
   |          |                |            |                |                |            | 0x44 0x44 0x49 |
   |          |                |            |                |                |            | 0x4E 0x47 0x00 |
   +----------+----------------+------------+----------------+----------------+------------+----------------+
   | **Data** |                                              | MIN_LENGTH     | 1          | 32             |
   +----------+                                              +----------------+------------+----------------+
   | **Hex**  |                                              | 0x4D 0x49 0x4E | 0x00 0x01  | 0x20           |
   |          |                                              | 0x5F 0x4C 0x45 |            |                |
   |          |                                              | 0x4E 0x47 0x54 |            |                |
   |          |                                              | 0x48 0x00      |            |                |
   +----------+----------------+------------+----------------+----------------+------------+----------------+
   | **Data** |                                              | ALGO           | 4          | CCM            |
   +----------+                                              +----------------+------------+----------------+
   | **Hex**  |                                              | 0x41 0x4C 0x47 | 0x00 0x04  | 0x43 0x43 0x4D |
   |          |                                              | 0x4F 0x00      |            | 0x00           |
   +----------+----------------+------------+----------------+----------------+------------+----------------+
   | **Data** | USAGE          | 31         | SIGN           | ALGO           | 19         | HMAC           |
   +----------+----------------+------------+----------------+----------------+------------+----------------+
   | *Hex**   | 0x55 0x53 0x41 | 0x00 0x1F  | 0x53 0x49 0x47 | 0x41 0x4C 0x47 | 0x00 0x13  | 0x48 0x4D 0x41 |
   |          | 0x47 0x45 0x00 |            | 0x4E 0x00      | 0x4F 0x00      |            | 0x43 0x00      |
   +----------+----------------+------------+----------------+----------------+------------+----------------+
   | **Data** |                                              | HASH           | 7          | SHA256         |
   +----------+                                              +----------------+------------+----------------+
   |**Hex**   |                                              | 0x48 0x41 0x53 | 0x00 0x07  | 0x53 0x48 0x41 |
   |          |                                              | 0x48 0x00      |            | 0x32 0x35 0x36 |
   |          |                                              |                |            | 0x00           |
   +----------+----------------+------------+----------------+----------------+------------+----------------+

