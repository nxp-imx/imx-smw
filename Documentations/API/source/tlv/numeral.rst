Numeral
=======
Definition
^^^^^^^^^^
As shown in the figure :numref:`tlv_numeral` below, a **numeral** is encoded with:

 -  *Type* is the name of the numeral to set.
 -  *Length* is the number of bytes of *Value*.
 -  *Value* is the numeric value in big-endian format.


.. figure:: figures/tlv_numeral.png
   :align: center
   :name: tlv_numeral

   TLV numeral data


Two categories of numeral are defined (see :numref:`tlv_numeral_type`); the C
standard type and the large numeral that is a hexdecimal buffer.

.. table:: TLV Numeral type
   :name: tlv_numeral_type
   :align: center
   :class: wrap-table

   +---------------+------------+
   | **Numeral**   | **Length** |
   +===============+============+
   | byte          | 1          |
   +---------------+------------+
   | short         | 2          |
   +---------------+------------+
   | integer       | 4          |
   +---------------+------------+
   | long long     | 8          |
   +---------------+------------+
   | large numeral | > 0        |
   +---------------+------------+

Examples
^^^^^^^^
The :numref:`tlv_short_example` is the coding of a short integer attribute
named *COUNTER* set to 500.

.. table:: Example of TLV short value
   :name: tlv_short_example
   :align: left
   :widths: 8 40 15 37
   :width: 100%
   :class: wrap-table

   +----------+-----------------------------------------+------------+-----------+
   |          | **Type**                                | **Length** | **Value** |
   +==========+=========================================+============+===========+
   | **Data** | COUNTER                                 | 2          | 500       |
   +----------+-----------------------------------------+------------+-----------+
   | **Hex**  | 0x43 0x4F 0x55 0x4E 0x54 0x45 0x52 0x00 | 0x00 0x02  | 0x01 0xF4 |
   +----------+-----------------------------------------+------------+-----------+

The :numref:`tlv_large_example` is the coding of a large integer attribute
named *RSA_PUB_EXP* set to 1,180,591,621,000,000,000,001.

.. table:: Example of TLV large value
   :name: tlv_large_example
   :align: left
   :widths: 8 40 15 37
   :width: 100%
   :class: wrap-table

   +----------+---------------------+------------+-------------------------------+
   |          | **Type**            | **Length** | **Value**                     |
   +==========+=====================+============+===============================+
   | **Data** | RSA_PUB_EXP         | 9          | 1,180,591,621,000,000,000,001 |
   +----------+---------------------+------------+-------------------------------+
   | **Hex**  | 0x52 0x53 0x41 0x5F | 0x00 0x09  | 0x40 0x00 0x00 0x00 0x41 0xCB |
   |          | 0x50 0x55 0x42 0x5F |            | 0x99 0x50 0x01                |
   |          | 0x45 0x58 0x50 0x00 |            |                               |
   +----------+---------------------+------------+-------------------------------+
