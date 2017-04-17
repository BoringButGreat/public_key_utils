defmodule TestData do
  data =
    File.ls!("test/data")
    |> Enum.filter(&(File.dir?("test/data/#{&1}")))
    |> Enum.flat_map(fn(source) ->
         File.ls!("test/data/#{source}")
         |> Enum.filter(&(File.dir?("test/data/#{source}/#{&1}")))
         |> Enum.flat_map(fn(alg) ->
              File.ls!("test/data/#{source}/#{alg}")
              |> Enum.filter(&(File.regular?("test/data/#{source}/#{alg}/#{&1}")))
              |> Enum.map(fn(file) ->
                   [base, type] = String.split(file, ".")
                   tags =
                     [source, alg | String.split(base, "_")]
                     |> Enum.map(&({String.to_atom(&1), true}))
                    tags = if alg == "rsa", do: [{:encryption, true} | tags], else: tags
                   file = File.read!("test/data/#{source}/#{alg}/#{file}")
                   {"#{source}/#{alg}/#{base}", type, tags, file}
                 end)
            end)
       end)
    |> Enum.reduce(%{}, fn({id, type, tags, file}, acc) ->
         which = acc[id] || %{}
         which = Map.put(which, type, %{tags: tags, file: file})
         Map.put(acc, id, which)
       end) |> IO.inspect

  def data, do: unquote(Macro.escape(data))
end
