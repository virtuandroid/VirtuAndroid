package com.lody.virtual.server.accounts

import android.accounts.Account
import androidx.annotation.CheckResult
import kotlinx.collections.immutable.PersistentList
import kotlinx.collections.immutable.PersistentMap
import kotlinx.collections.immutable.persistentHashMapOf
import kotlinx.collections.immutable.persistentListOf
import kotlinx.collections.immutable.toPersistentList

data class VAccountTable(
    /** Key = VirtualXposed UserID, value = Shared list of accounts */
    private val accountsByUserId: PersistentMap<Int, PersistentList<VAccount>>
) {
    @CheckResult
    fun getAll(): List<VAccount> {
        return accountsByUserId.values.flatten()
    }

    @CheckResult
    fun getAccounts(userId: Int): PersistentList<VAccount>? {
        return accountsByUserId[userId]
    }

    @CheckResult
    fun getAccount(userId: Int, account: Account): VAccount? {
        return getAccount(userId, account.name, account.type)
    }

    @CheckResult
    fun getAccount(userId: Int, name: String?, type: String?): VAccount? {
        val users = accountsByUserId[userId]
        return users?.firstOrNull { it.name == name && it.type == type }
    }

    @CheckResult
    fun modifyAccount(
        userId: Int,
        account: Account,
        mutation: (VAccount) -> VAccount
    ): Pair<Boolean, VAccountTable> {
        return modifyAccount(userId, account.name, account.type, mutation)
    }

    /** @return change status paired to the new table. The change status is false if nothing is modified. */
    @CheckResult
    fun modifyAccount(
        userId: Int,
        name: String?,
        type: String?,
        mutation: (VAccount) -> VAccount
    ): Pair<Boolean, VAccountTable> {
        val oldList = accountsByUserId[userId] ?: return false to this
        val oldUser = getAccount(userId, name, type) ?: return false to this
        val newUser = mutation.invoke(oldUser)
        // We can early return here since VAccount is immutable
        if (newUser === oldUser) {
            return false to this
        }

        val index = oldList.indexOf(oldUser)
        val newList = oldList.replacingAt(index, newUser)

        val newTable = accountsByUserId.putting(userId, newList)

        return true to VAccountTable(newTable)
    }

    @CheckResult
    fun modifyAccounts(
        userId: Int,
        mutation: (VAccount) -> VAccount?
    ): Pair<Boolean, VAccountTable> {
        val oldList = accountsByUserId[userId] ?: return false to this
        var changed = false
        val newList = oldList.mapNotNull {
            val newItem = mutation.invoke(it)
            if (!changed && newItem !== it) {
                changed = true
            }
            newItem
        }.toPersistentList()

        val newTable = accountsByUserId.putting(userId, newList)

        return changed to VAccountTable(newTable)
    }

    @CheckResult
    fun addAccount(userId: Int, account: VAccount): VAccountTable {
        val oldList = accountsByUserId[userId] ?: persistentListOf()
        val newList = oldList.adding(account)

        val newTable = accountsByUserId.putting(userId, newList)
        return VAccountTable(newTable)
    }

    @CheckResult
    fun removeAccount(userId: Int, name: String?, type: String?): Pair<Boolean, VAccountTable> {
        val oldList = accountsByUserId[userId] ?: return false to this
        val oldUser = getAccount(userId, name, type) ?: return false to this
        val newList = oldList.removing(oldUser)

        val newTable = accountsByUserId.putting(userId, newList)
        return true to VAccountTable(newTable)
    }


//    fun get(pid: Int): ProcessRecord? = byPid[pid]
//    fun get(name: String?, vuid: Int): ProcessRecord? =
//        pidByName[ProcessIdentifier(name, vuid)]?.let(byPid::get)

//    val all: Collection<ProcessRecord> get() = byPid.values

//    fun set(rec: ProcessRecord): ProcessTable {
//        val identifier = ProcessIdentifier(rec.processName, rec.vuid)
//        val names = pidByName.putting(identifier, rec.pid)
//        return ProcessTable(byPid.putting(rec.pid, rec), names)
//    }

//    fun remove(rec: ProcessRecord): ProcessTable {
//        val identifier = ProcessIdentifier(rec.processName, rec.vuid)
//        return ProcessTable(byPid.removing(rec.pid, rec), pidByName.removing(identifier, rec.pid))
//    }

    companion object {
        val EMPTY = VAccountTable(persistentHashMapOf())
    }
}