defmodule Tamandua.IocAuthorityMultinodeSmoke.NodeRuntime do
  @moduledoc false

  @state __MODULE__.State
  @executor "tamandua_authority_ioc_snapshot_v1_executor"
  @columns ~w(authority_epoch is_envelope has_more row_bytes id organization_id type value severity description source)
  @page_size 1_000
  @maximum_rows 100_000
  @maximum_bytes 64 * 1024 * 1024
  @maximum_row_bytes 64 * 1024
  @wall_timeout_ms 30_000

  def start do
    Application.ensure_all_started(:postgrex)
    Application.ensure_all_started(:ecto)

    case Agent.start_link(fn -> %{snapshot: nil, publications: 0} end, name: @state) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
    end
  end

  def state, do: Agent.get(@state, & &1)

  def reconcile(database_options) do
    before = state()

    result =
      with {:ok, connection} <- Postgrex.start_link(database_options) do
        try do
          with {:ok, snapshot} <- read_snapshot(connection) do
            publish(before, snapshot)
          end
        after
          stop_connection(connection)
        end
      else
        {:error, reason} -> {:error, normalize_error(reason)}
      end

    case result do
      {:ok, next, outcome} ->
        Agent.update(@state, fn _ -> next end)
        {:ok, outcome, next}

      {:error, reason} ->
        {:error, reason, state()}
    end
  rescue
    _error -> {:error, :snapshot_unavailable, state()}
  catch
    :exit, _reason -> {:error, :snapshot_unavailable, state()}
  end

  defp read_snapshot(connection) do
    started_at = System.monotonic_time(:millisecond)

    Postgrex.transaction(
      connection,
      fn transaction ->
        with {:ok, _} <-
               Postgrex.query(
                 transaction,
                 "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY",
                 []
               ),
             {:ok, _} <- Postgrex.query(transaction, "SET LOCAL ROLE #{@executor}", []),
             {:ok, page} <- read_pages(transaction, nil, nil, [], 0, started_at),
             {:ok, digest} <-
               TamanduaServer.IocSnapshotDigest.sha256(
                 page.epoch,
                 length(page.rows),
                 page.byte_count,
                 page.rows
               ) do
          %{epoch: page.epoch, digest: digest, count: length(page.rows)}
        else
          error -> Postgrex.rollback(transaction, error)
        end
      end,
      timeout: @wall_timeout_ms + 1_000
    )
    |> case do
      {:ok, snapshot} -> {:ok, snapshot}
      {:error, reason} -> {:error, reason}
    end
  end

  defp read_pages(connection, expected_epoch, after_id, reversed_rows, byte_count, started_at) do
    sql =
      "SELECT * FROM public.authority_ioc_snapshot_v1(" <>
        "$1::bigint, $2::uuid, $3::integer)"

    with :ok <- within_wall_time(started_at),
         {:ok, %{columns: @columns, rows: raw_rows}} <-
           Postgrex.query(connection, sql, [expected_epoch, uuid_param(after_id), @page_size],
             timeout: 5_000
           ) do
      case raw_rows do
        [[epoch, true, false, 0, nil, nil, nil, nil, nil, nil, nil]]
        when is_integer(epoch) and epoch >= 0 and
               (is_nil(expected_epoch) or expected_epoch == epoch) and is_nil(after_id) ->
          {:ok, %{epoch: epoch, rows: Enum.reverse(reversed_rows), byte_count: byte_count}}

        rows when is_list(rows) and rows != [] and length(rows) <= @page_size ->
          parsed = Enum.map(rows, &parse_row/1)
          epoch = parsed |> hd() |> Map.fetch!(:epoch)
          flags = parsed |> Enum.map(& &1.has_more) |> Enum.uniq()
          page_rows = Enum.map(parsed, & &1.row)
          page_bytes = Enum.sum(Enum.map(parsed, & &1.row_bytes))

          if Enum.all?(parsed, &(&1.epoch == epoch)) and
               (is_nil(expected_epoch) or expected_epoch == epoch) and
               ((flags == [true] and length(page_rows) == @page_size) or flags == [false]) and
               length(reversed_rows) + length(page_rows) <= @maximum_rows and
               byte_count + page_bytes <= @maximum_bytes do
            next_rows = Enum.reverse(page_rows, reversed_rows)
            next_bytes = byte_count + page_bytes
            last_id = page_rows |> List.last() |> Map.fetch!(:id)

            if flags == [true] do
              read_pages(connection, epoch, last_id, next_rows, next_bytes, started_at)
            else
              {:ok, %{epoch: epoch, rows: Enum.reverse(next_rows), byte_count: next_bytes}}
            end
          else
            {:error, :malformed_snapshot}
          end

        _other ->
          {:error, :malformed_snapshot}
      end
    else
      _error -> {:error, :malformed_snapshot}
    end
  end

  defp parse_row([
         epoch,
         false,
         has_more,
         row_bytes,
         id,
         organization_id,
         type,
         value,
         severity,
         description,
         source
       ])
       when is_integer(epoch) and epoch >= 0 and is_boolean(has_more) and
              is_integer(row_bytes) and row_bytes in 1..@maximum_row_bytes and is_binary(id) and
              (is_nil(organization_id) or is_binary(organization_id)) and is_binary(type) and
              is_binary(value) and is_binary(severity) and
              (is_nil(description) or is_binary(description)) and
              (is_nil(source) or is_binary(source)) do
    %{
      epoch: epoch,
      has_more: has_more,
      row_bytes: row_bytes,
      row: %{
        id: uuid_string(id),
        organization_id: nullable_uuid_string(organization_id),
        type: type,
        value: value,
        severity: severity,
        description: description,
        source: source
      }
    }
  end

  defp publish(%{snapshot: nil} = state, snapshot) do
    next = %{state | snapshot: snapshot, publications: state.publications + 1}
    {:ok, next, :published}
  end

  defp publish(%{snapshot: current} = state, snapshot) do
    cond do
      snapshot.epoch < current.epoch ->
        {:error, :stale_epoch}

      snapshot.epoch == current.epoch and snapshot.digest != current.digest ->
        {:error, :epoch_digest_conflict}

      snapshot.epoch == current.epoch ->
        {:ok, state, :verified_unchanged}

      true ->
        next = %{state | snapshot: snapshot, publications: state.publications + 1}
        {:ok, next, :published}
    end
  end

  defp uuid_string(<<_::128>> = uuid), do: Ecto.UUID.load!(uuid)
  defp uuid_string(uuid) when is_binary(uuid), do: Ecto.UUID.cast!(uuid)
  defp nullable_uuid_string(nil), do: nil
  defp nullable_uuid_string(uuid), do: uuid_string(uuid)
  defp uuid_param(nil), do: nil
  defp uuid_param(uuid), do: Ecto.UUID.dump!(uuid)

  defp within_wall_time(started_at) do
    if System.monotonic_time(:millisecond) - started_at < @wall_timeout_ms,
      do: :ok,
      else: {:error, :snapshot_timeout}
  end

  defp stop_connection(connection) do
    if Process.alive?(connection), do: GenServer.stop(connection, :normal, 1_000)
  catch
    :exit, _reason -> :ok
  end

  defp normalize_error(_reason), do: :snapshot_unavailable
end

defmodule Tamandua.IocAuthorityMultinodeSmoke do
  @moduledoc false

  alias Tamandua.IocAuthorityMultinodeSmoke.NodeRuntime

  def run! do
    started_at = DateTime.utc_now()

    assert!(
      System.get_env("IOC_SMOKE_DESTRUCTIVE_CONFIRMED") == "disposable-database-only",
      "IOC smoke mutates IOCs and may run only against a disposable database"
    )

    ensure_distributed!()
    Application.ensure_all_started(:postgrex)
    Application.ensure_all_started(:ecto)

    database = database_options()
    admin = admin_options()
    peers = start_peers!()

    try do
      Enum.each(peers, fn {_peer, node} ->
        load_runtime!(node)
        :ok = rpc!(node, NodeRuntime, :start, [])
      end)

      [{_peer_a, node_a}, {_peer_b, node_b}] = peers
      {:ok, :published, initial_a} = rpc!(node_a, NodeRuntime, :reconcile, [database])
      {:ok, :published, initial_b} = rpc!(node_b, NodeRuntime, :reconcile, [database])
      assert_same_snapshot!(initial_a, initial_b)

      insert_new_ioc!(admin)

      {:ok, :published, advanced_a} = rpc!(node_a, NodeRuntime, :reconcile, [database])

      failed_database = Keyword.put(database, :port, 1)

      {:error, :snapshot_unavailable, failed_b} =
        rpc!(node_b, NodeRuntime, :reconcile, [failed_database])

      assert!(failed_b == initial_b, "failed node replaced its prior generation")

      {:ok, :published, recovered_b} = rpc!(node_b, NodeRuntime, :reconcile, [database])
      assert_same_snapshot!(advanced_a, recovered_b)

      assert!(
        recovered_b.publications == initial_b.publications + 1,
        "recovery did not publish exactly once"
      )

      {:ok, :verified_unchanged, verified_b} =
        rpc!(node_b, NodeRuntime, :reconcile, [database])

      assert!(verified_b.publications == recovered_b.publications, "equal snapshot republished")

      IO.inspect(
        %{
          evidence_class: :synthetic_multinode_smoke,
          started_at: DateTime.to_iso8601(started_at),
          completed_at: DateTime.utc_now() |> DateTime.to_iso8601(),
          nodes: Enum.map(peers, fn {_peer, node} -> node end),
          authority_epoch: recovered_b.snapshot.epoch,
          digest: recovered_b.snapshot.digest,
          count: recovered_b.snapshot.count,
          node_a_publications: advanced_a.publications,
          node_b_publications: recovered_b.publications,
          failure_preserved_generation: true,
          recovery_published_exactly_once: true,
          equal_generation_verified_without_republish: true
        },
        label: "IOC_AUTHORITY_MULTINODE_SMOKE"
      )
    after
      Enum.each(peers, fn {peer, _node} -> stop_peer(peer) end)
    end
  end

  defp start_peers! do
    first = start_peer!(:ioc_authority_node_a)

    try do
      [first, start_peer!(:ioc_authority_node_b)]
    rescue
      error ->
        stop_peer(elem(first, 0))
        reraise error, __STACKTRACE__
    catch
      kind, reason ->
        stop_peer(elem(first, 0))
        :erlang.raise(kind, reason, __STACKTRACE__)
    end
  end

  defp start_peer!(name) do
    paths = Enum.flat_map(:code.get_path(), fn path -> [~c"-pa", path] end)
    {:ok, peer, node} = :peer.start_link(%{name: name, args: paths})
    {peer, node}
  end

  defp load_runtime!(node) do
    {:module, NodeRuntime, binary, filename} = :code.get_object_code(NodeRuntime)
    {:module, NodeRuntime} = rpc!(node, :code, :load_binary, [NodeRuntime, filename, binary])
  end

  defp insert_new_ioc!(options) do
    {:ok, connection} = Postgrex.start_link(options)

    try do
      id = Ecto.UUID.generate() |> Ecto.UUID.dump!()

      {:ok, _} =
        Postgrex.query(
          connection,
          "INSERT INTO public.iocs " <>
            "(id, organization_id, type, value, severity, description, source, enabled, " <>
            "inserted_at, updated_at) " <>
            "VALUES ($1::uuid, NULL, 'domain', $2, 'high', 'multinode recovery', " <>
            "'smoke', true, pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp())",
          [id, "multinode-#{System.unique_integer([:positive])}.test"]
        )
    after
      stop_connection(connection)
    end
  end

  defp stop_connection(connection) do
    if Process.alive?(connection), do: GenServer.stop(connection, :normal, 1_000)
  catch
    :exit, _reason -> :ok
  end

  defp stop_peer(peer) do
    :peer.stop(peer)
  catch
    :exit, _reason -> :ok
  end

  defp assert_same_snapshot!(left, right) do
    assert!(left.snapshot.epoch == right.snapshot.epoch, "nodes diverged on epoch")
    assert!(left.snapshot.digest == right.snapshot.digest, "nodes diverged on digest")
    assert!(left.snapshot.count == right.snapshot.count, "nodes diverged on count")
  end

  defp database_options do
    [
      hostname: env!("IOC_SMOKE_PGHOST"),
      port: env_integer("IOC_SMOKE_PGPORT", 5432),
      username: env!("IOC_SMOKE_PGUSER"),
      password: env!("IOC_SMOKE_PGPASSWORD"),
      database: env!("IOC_SMOKE_PGDATABASE"),
      connect_timeout: 2_000
    ]
  end

  defp admin_options do
    database_options()
    |> Keyword.put(:username, env!("IOC_SMOKE_ADMIN_USER"))
    |> Keyword.put(:password, env!("IOC_SMOKE_ADMIN_PASSWORD"))
  end

  defp ensure_distributed! do
    assert!(Node.alive?(), "run with --sname so two real BEAM peers can start")
  end

  defp rpc!(node, module, function, args) do
    case :rpc.call(node, module, function, args, 15_000) do
      {:badrpc, reason} -> raise "RPC failed: #{inspect(reason)}"
      result -> result
    end
  end

  defp env!(name), do: System.fetch_env!(name)

  defp env_integer(name, default),
    do: System.get_env(name, Integer.to_string(default)) |> String.to_integer()

  defp assert!(true, _message), do: :ok
  defp assert!(false, message), do: raise(message)
end

if System.get_env("IOC_SMOKE_RUN") == "true" do
  Tamandua.IocAuthorityMultinodeSmoke.run!()
end
