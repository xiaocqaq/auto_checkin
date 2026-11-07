import { useEffect, useState } from 'react'
import { Dropdown, DropdownItem, DropdownMenu, DropdownTrigger } from '@heroui/react'
import { MonitorIcon, MoonIcon, SunIcon } from './icons'
import { repaintIfFollowing, resolveTheme, setChoice, storedChoice, type ThemeChoice } from './theme'

/** 三选一：跟随系统 / 亮色 / 暗色。
 *
 *  做成下拉菜单而不是一个「亮↔暗」开关，是因为开关只能表达两个状态：一旦写成开关，
 *  「跟随系统」就没有位置可放 —— 用户既看不见它，也没法选中它回来。三态就该有三个位置。
 *
 *  触发器显示**当前是哪个模式**（不是「按下去会变成什么」）：菜单的入口应当回答「我现在
 *  是什么样」，点开之后才是在三个模式里挑一个。跟随系统时显示显示器图标，且菜单里
 *  「跟随系统」那一行带上设备眼下的实际结果，省得猜。 */
const OPTIONS: { key: ThemeChoice; label: string; Icon: typeof SunIcon }[] = [
  { key: 'system', label: '跟随系统', Icon: MonitorIcon },
  { key: 'light', label: '亮色', Icon: SunIcon },
  { key: 'dark', label: '暗色', Icon: MoonIcon },
]

export default function ThemeToggle() {
  const [choice, setLocal] = useState<ThemeChoice>(storedChoice)
  /** 设备眼下的亮暗。单独存一份是为了让菜单里「现在设备是暗色」这句话不会说错：
   *  跟随系统时它会在系统翻转后更新，选择本身（choice）不变。 */
  const [showing, setShowing] = useState(() => resolveTheme(storedChoice()))

  /** 跟随系统时，设备主题一变就重画（入夜转暗、手机日落切换）。选了亮/暗的人不该被拖走，
   *  这个判断在 theme.repaintIfFollowing 里。 */
  useEffect(() => {
    const mq = window.matchMedia?.('(prefers-color-scheme: dark)')
    if (!mq) return
    const onChange = () => setShowing(repaintIfFollowing())
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])

  const current = OPTIONS.find((o) => o.key === choice) ?? OPTIONS[0]
  const label =
    choice === 'system'
      ? `主题：跟随系统（当前${showing === 'dark' ? '暗色' : '亮色'}）`
      : `主题：${current.label}`

  return (
    <Dropdown placement="bottom-end">
      <DropdownTrigger>
        <button
          type="button"
          aria-label={label}
          title={label}
          className="grid h-8 w-8 shrink-0 place-items-center rounded-medium text-default-500 outline-none transition-colors hover:bg-default-100 hover:text-default-700 focus-visible:ring-2 focus-visible:ring-focus"
        >
          <current.Icon className="h-[18px] w-[18px]" />
        </button>
      </DropdownTrigger>
      <DropdownMenu
        aria-label="选择主题"
        selectionMode="single"
        selectedKeys={[choice]}
        onSelectionChange={(keys) => {
          // 'all' 只在 multiple 下出现；这里 keys 恒为单值集合。
          if (keys === 'all') return
          const picked = Array.from(keys)[0] as ThemeChoice | undefined
          if (!picked) return
          setChoice(picked)
          setLocal(picked)
          // 切到「跟随系统」时要把眼下的设备结果算出来，否则菜单里的描述会沿用上一次的。
          setShowing(resolveTheme(picked))
        }}
      >
        {OPTIONS.map(({ key, label: text, Icon }) => (
          <DropdownItem
            key={key}
            startContent={<Icon className="h-4 w-4" />}
            description={
              key === 'system'
                ? `现在设备是${showing === 'dark' ? '暗色' : '亮色'}，跟着它变`
                : undefined
            }
          >
            {text}
          </DropdownItem>
        ))}
      </DropdownMenu>
    </Dropdown>
  )
}
