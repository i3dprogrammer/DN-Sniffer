using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DNSecurityAPI;

namespace DNSniffer.Bots
{
    //For Talismans, Jades, Heraldries only DO NOT ATTEMPT TO OPEN POUCHES or Chaos Heraldry!
    class BoxOpenerBot : IBot
    {
        Inventory inventory;
        Context TCPRemoteContext;
        bool boxOpenerWorking = false;
        bool openingBoxStep1 = false;
        bool openingBoxStep2 = false;
        Item boxItem;
        List<byte> JadeSlots = new List<byte>();
        bool sellJades = false;

        public BoxOpenerBot(ref Context remote_context)
        {
            TCPRemoteContext = remote_context;

            Console.WriteLine("How to use Box Opener:");
            Console.WriteLine("1. Typing \"open\" in the console will start opening boxes until inventory is full");
            Console.WriteLine("2. Typing \"sell\" in the console will sell all the gained items that are not stored in the storage.");
            Console.WriteLine("Note: Make sure to stand near Berlin Blacksmith in Ch5 if you want to sell items.");
        }

        public void ProcessPacket(Packet packet, Context context, Context remote_context, Context local_context)
        {
            if (context == remote_context && packet.Opcode == 0x0701) //Inventory items list
            {
                inventory = new Inventory();
                inventory.TotalSlots = packet.ReadUInt8();
                int counter = packet.ReadUInt8();

                for (int i = 0; i < counter; i++)
                {
                    var item = new Item(packet);
                    inventory.AddItem(item);
                }

                Console.WriteLine($"Free slots {inventory.TotalSlots} - {inventory.UsedSlots} = {inventory.FreeSlots}");
            }
            else if (context == remote_context && packet.Opcode == 0x070A) //Item updated (removed, add)
            {
                var operation = packet.ReadUInt8();
                var slotAffected = packet.ReadUInt8();

                var itemID = packet.ReadUInt32();

                if (operation == 0x00) //Item Updated
                {
                    if (itemID == 0x00) //Item sold
                    {
                        inventory.RemoveItem(slotAffected);
                        Console.WriteLine($"Item at {slotAffected} is removed.");
                        if (JadeSlots.Contains(slotAffected))
                            JadeSlots.Remove(slotAffected);
                    }
                    else //Item count updated.
                    {
                        if (inventory.Items.ContainsKey(slotAffected))
                        {
                            packet.ReadUInt8Array(0x0E);
                            inventory.Items[slotAffected].Count = packet.ReadUInt16();
                        }
                        else
                        {
                            Console.WriteLine("DAFUQ is going on? how to update an item I've never heard of.");
                        }
                    }
                }
                else //Item added
                {
                    Item item = new Item();
                    item.Slot = slotAffected;
                    item.ItemID = itemID;
                    item.UsageID = packet.ReadUInt64();
                    packet.ReadUInt8Array(0x06);
                    item.Count = packet.ReadUInt16();

                    if (inventory.Items.ContainsKey(item.Slot))
                        inventory.Items[item.Slot] = item;
                    else
                        inventory.AddItem(item);

                    Console.WriteLine($"Gained item at {slotAffected}");

                    if (boxOpenerWorking)
                        JadeSlots.Add(slotAffected);
                }
            }
            else if (context == remote_context && packet.Opcode == 0x0704) //Item change in inventory.
            {
                var action = packet.ReadUInt8();
                packet.ReadUInt32();

                var item1 = new Item(packet);
                var item2 = new Item(packet);

                if (action == 0x02) //Move in inventory
                {
                    bool splitted = (!inventory.Items.ContainsKey(item1.Slot) || !inventory.Items.ContainsKey(item2.Slot));

                    inventory.Items[item1.Slot] = item1;
                    inventory.Items[item2.Slot] = item2;

                    if (item1.ItemID == 0x00)
                    {
                        inventory.RemoveItem(item1.Slot);
                        Console.WriteLine($"Item moved from {item1.Slot} to {item2.Slot}");

                        if (JadeSlots.Contains(item1.Slot))
                        {
                            JadeSlots.Remove(item1.Slot);
                            JadeSlots.Add(item2.Slot);
                        }
                    }
                    else if (item2.ItemID == 0x00)
                    {   //Never happens
                        inventory.RemoveItem(item2.Slot);
                        Console.WriteLine($"###Item moved from {item2.Slot} to {item1.Slot}");
                    }
                    else
                    {
                        if (splitted)
                            Console.WriteLine($"Item splitted from {item1.Slot} to {item2.Slot}");
                        else
                            Console.WriteLine($"Item swapped from {item1.Slot} to {item2.Slot}");

                        if (JadeSlots.Contains(item1.Slot) && JadeSlots.Contains(item2.Slot))
                        {
                            //Swapped jades together, doesn't matter in our case.
                        }
                        else if (JadeSlots.Contains(item1.Slot))
                        {
                            JadeSlots.Remove(item1.Slot);
                            JadeSlots.Add(item2.Slot);
                        }
                        else if (JadeSlots.Contains(item2.Slot))
                        {
                            JadeSlots.Remove(item2.Slot);
                            JadeSlots.Add(item1.Slot);
                        }
                    }
                }
                else if (action == 0x07) //Move item from inventory to storage
                {
                    inventory.RemoveItem(item1.Slot);

                    if (JadeSlots.Contains(item1.Slot))
                        JadeSlots.Remove(item1.Slot);

                    Console.WriteLine("Stored item : " + item1.Slot);
                }
                else if (action == 0x08) //Move item from storage to inventory
                {
                    inventory.AddItem(item2);
                    Console.WriteLine("Gained item from storage at : " + item2.Slot);
                }
            } else if(context == remote_context && packet.Opcode == 0x0707)
            {
                packet.ReadUInt8Array(0x05);
                var item = new Item(packet);
                Console.WriteLine("Removed item at : " + item.Slot);

                inventory.RemoveItem(item.Slot);

                if (JadeSlots.Contains(item.Slot))
                    JadeSlots.Remove(item.Slot);
            }
            else if (context == remote_context && packet.Opcode == 0x072F && boxOpenerWorking) //If we received box opening response
            {
                packet.ReadUInt8Array(0x05);
                var action = packet.ReadUInt8();
                if (action == 0x05)
                {
                    if (openingBoxStep2)
                        return;
                    openingBoxStep2 = true;
                    Task.Run(() =>
                    {
                        Thread.Sleep(2100);

                        Packet p2 = new Packet(0x08, 0x08);
                        p2.WriteUInt8(0x02);
                        p2.WriteUInt16(boxItem.Slot);
                        p2.WriteUInt64(boxItem.UsageID);
                        p2.WriteUInt8Array(new byte[0x05]);

                        remote_context.Security.Send(p2);

                        openingBoxStep1 = false;
                        openingBoxStep2 = false;
                    });
                }
                else if (action == 0x07)
                {
                    OpenJadeBox(remote_context);
                }
            }
            else if (context == remote_context && packet.Opcode == 0x0E02 && sellJades) //Item sold complete.
            {
                SellJades(remote_context);
            } else if(context == remote_context && packet.Opcode == 0x0901 && sellJades) //Opened Store
            {
                if(packet.GetBytes().Sum(x => x) > 0xFF) //We didnt select store option yet.
                {
                    var p = new Packet(0x09, 0x01);
                    p.WriteUInt8Array(new byte[] { 0x70, 0x00, 0x00, 0x80, 0x7C, 0x80, 0xA4, 0x24, 0x82, 0x8C, 0x63, 0xAB });

                    remote_context.Security.Send(p);
                } else //We selected store option Purchase/Sell
                {
                    SellJades(remote_context);
                }
            }
        }

        public void SellJades(Context remote_context)
        {
            if (JadeSlots.Count == 0)
            {
                sellJades = false;
                return;
            }

            sellJades = true;

            var firstSlot = JadeSlots[0];

            if (!inventory.Items.ContainsKey(firstSlot))
                return;

            var packet = new Packet(0x0E, 0x01);
            var item = inventory.Items[firstSlot];

            packet.WriteUInt8(item.Slot);
            packet.WriteUInt8Array(new byte[] { 0x01, 0x00 });
            packet.WriteUInt64(item.UsageID);
            remote_context.Security.Send(packet);
        }

        public void OpenJadeBox(Context rem_context)
        {
            boxItem = inventory.Items.FirstOrDefault(x => 
                x.Value.ItemID == 536878215 ||
                x.Value.ItemID == 536878214 || 
                x.Value.ItemID == 536878213 ||
                x.Value.ItemID == 268476598).Value;

            if (boxItem == null)
            {
                Console.WriteLine("Couldn't find mysterious box item.");
                boxOpenerWorking = false;
                return;
            }
            else if (inventory.FreeSlots == 0)
            {
                Console.WriteLine("No free slots, stopping process.");
                boxOpenerWorking = false;
                return;
            } else if(openingBoxStep1 || openingBoxStep2)
            {
                Console.WriteLine("Phew! Just dodged an item error!");
                return;
            }

            openingBoxStep1 = true;

            Console.WriteLine($"Free slots {inventory.TotalSlots} - {inventory.UsedSlots} = {inventory.FreeSlots}, Got {boxItem.Count} boxes left.");

            Packet p1 = new Packet(0x08, 0x07);
            p1.WriteUInt8(0x02);
            p1.WriteUInt16(boxItem.Slot);
            p1.WriteUInt64(boxItem.UsageID);
            p1.WriteUInt8Array(new byte[0x05]);

            boxOpenerWorking = true;
            rem_context.Security.Send(p1);
        }

        public void ShowInfo()
        {
            var item = inventory.Items.FirstOrDefault(x => x.Value.ItemID == 536878215).Value;
            if(item == null)
                Console.WriteLine("You don't have myesterious jade box");
            else
                Console.WriteLine($"You own {item.Count} jade boxes");

            Console.WriteLine($"Got {inventory.FreeSlots} free slots");

            foreach(var i in inventory.Items)
                Console.WriteLine($"#{i.Value.Slot} - {i.Value.ItemID}");
        }

        public void StartSellinJades(Context remote_context)
        {
            sellJades = true;

            Packet p = new Packet(0x09, 0x01);
            p.WriteUInt8Array(new byte[] { 0x70, 0x00, 0x00, 0x80, 0xD3, 0x49, 0x61, 0x10, 0x82, 0x8C, 0x63, 0xAB });

            remote_context.Security.Send(p);
        }

        class Inventory
        {
            public byte TotalSlots { get; set; } = 0;
            public byte UsedSlots { get; set; } = 0;
            public int FreeSlots
            {
                get
                {
                    return (TotalSlots - UsedSlots);
                }
            }
            public Dictionary<byte, Item> Items = new Dictionary<byte, Item>();

            public void AddItem(Item item)
            {
                Items.Add(item.Slot, item);
                UsedSlots += 1;
            }

            public void RemoveItem(byte slot)
            {
                Items.Remove(slot);
                UsedSlots -= 1;
            }
        }

        class Item
        {
            public byte Slot { get; set; }
            public UInt32 ItemID { get; set; }
            public UInt16 Count { get; set; }
            public UInt64 UsageID { get; set; }

            public Item() { }
            public Item(Packet packet)
            {
                this.Slot = packet.ReadUInt8();
                this.ItemID = packet.ReadUInt32();
                this.UsageID = packet.ReadUInt64();
                packet.ReadUInt8Array(0x06);
                this.Count = packet.ReadUInt16();
                packet.ReadUInt8Array(0x1D);
            }

        }
    }
}
